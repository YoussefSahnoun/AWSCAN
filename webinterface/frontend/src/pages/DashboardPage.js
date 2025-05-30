import React, { useState, useEffect } from 'react';
import { AppBar, Toolbar, Typography, Button, Box, Grid, Card, Modal, Table, TableBody, TableCell, TableContainer, TableHead, TableRow, Paper, TextField } from '@mui/material';
import NewScanModal from '../components/NewScanModal';
import ScanHistory from '../components/ScanHistory';
import { Bar, Pie } from 'react-chartjs-2';
import { Chart as ChartJS, CategoryScale, LinearScale, BarElement, ArcElement, Tooltip, Legend } from 'chart.js';

ChartJS.register(CategoryScale, LinearScale, BarElement, ArcElement, Tooltip, Legend);

function extractTimestamp(filename) {
    // Example: scan_20250530132136
    const match = filename.match(/scan_(\d{14})/);
    if (!match) return null;
    const ts = match[1];
    const year = ts.slice(0, 4);
    const month = ts.slice(4, 6);
    const day = ts.slice(6, 8);
    const hour = ts.slice(8, 10);
    const min = ts.slice(10, 12);
    const sec = ts.slice(12, 14);
    return new Date(`${year}-${month}-${day}T${hour}:${min}:${sec}Z`);
}

function DashboardPage() {
    const [scans, setScans] = useState([]);
    const [loadingScans, setLoadingScans] = useState(false);
    const [showScanReportsModal, setShowScanReportsModal] = useState(false);
    const [showNewScanModal, setShowNewScanModal] = useState(false);
    const [searchTerm, setSearchTerm] = useState('');
    // For scan report charts
    const [selectedReportScan, setSelectedReportScan] = useState(null);
    const [reportScanData, setReportScanData] = useState(null);
    const [reportScanLoading, setReportScanLoading] = useState(false);

    // Fetch scans for scan history (on mount)
    useEffect(() => {
        fetch('http://localhost:5000/scans/')
            .then(res => res.json())
            .then(data => {
                setScans(data.map((scan, idx) => ({
                    id: idx,
                    name: scan.filename,
                    timestamp: extractTimestamp(scan.filename),
                    status: scan.status || 'unknown',
                })));
            });
    }, []);

    // Fetch scans from backend when modal opens (for reports)
    useEffect(() => {
        if (showScanReportsModal) {
            setLoadingScans(true);
            fetch('http://localhost:5000/scans/')
                .then(res => res.json())
                .then(data => {
                    setScans(data.map((scan, idx) => ({
                        id: idx,
                        name: scan.filename,
                        timestamp: extractTimestamp(scan.filename),
                        status: scan.status || 'unknown',
                    })));
                    setLoadingScans(false);
                })
                .catch(() => setLoadingScans(false));
        }
    }, [showScanReportsModal]);

    // Filter and sort scans for scan history
    const filteredScans = scans
        .filter(scan => scan.timestamp && scan.name.toLowerCase().includes(searchTerm.toLowerCase()))
        .sort((a, b) => b.timestamp - a.timestamp)
        .slice(0, 5);

    // Metrics calculation
    const totalScans = scans.length;

    // --- Scan Report Chart Modal Logic ---
    // Flatten raw_results if present
    let allChecks = [];
    if (reportScanData && Array.isArray(reportScanData.raw_results)) {
        allChecks = reportScanData.raw_results.flat();
    }

    let servicesChart = null;
    let passFailChart = null;
    let servicesList = null;

    if (allChecks.length > 0) {
        // Services checked: count per service in allChecks
        const serviceCounts = {};
        const serviceChecks = {};
        allChecks.forEach(r => {
            const service = r.service || 'Unknown';
            serviceCounts[service] = (serviceCounts[service] || 0) + 1;
            if (!serviceChecks[service]) serviceChecks[service] = [];
            serviceChecks[service].push(r);
        });

        // Bar chart for number of checks per service
        const serviceLabels = Object.keys(serviceCounts);
        const serviceValues = Object.values(serviceCounts);

        servicesChart = (
            <Bar
                data={{
                    labels: serviceLabels,
                    datasets: [
                        {
                            label: 'Checks per Service',
                            data: serviceValues,
                            backgroundColor: [
                                '#36A2EB', '#4CAF50', '#FFB300', '#FF5722', '#AB47BC', '#26A69A', '#789262'
                            ],
                            borderRadius: 6,
                        },
                    ],
                }}
                options={{
                    responsive: true,
                    plugins: {
                        legend: { display: false },
                        title: { display: false },
                        tooltip: {
                            callbacks: {
                                label: function(context) {
                                    return `${context.dataset.label}: ${context.parsed.y}`;
                                }
                            }
                        }
                    },
                    scales: {
                        x: {
                            ticks: { color: '#B3E5FC', font: { weight: 'bold' } },
                            grid: { color: '#333' }
                        },
                        y: {
                            beginAtZero: true,
                            ticks: { color: '#B3E5FC', font: { weight: 'bold' } },
                            grid: { color: '#333' }
                        }
                    }
                }}
                height={220}
            />
        );

        // List of services checked, with number of checks and a preview of check names
        servicesList = (
            <ul style={{ paddingLeft: 0, marginTop: 16 }}>
                {serviceLabels.map(service => (
                    <li key={service} style={{ marginBottom: 10, color: '#B3E5FC', background: '#23243a', borderRadius: 6, padding: 8 }}>
                        <strong>{service}</strong> — {serviceCounts[service]} checks
                        <ul style={{ margin: '6px 0 0 12px', color: '#fff', fontSize: 13 }}>
                            {serviceChecks[service].slice(0, 3).map((check, idx) => (
                                <li key={idx}>
                                    {check.check_id ? <span style={{ color: '#FFB300' }}>{check.check_id}: </span> : null}
                                    {check.title || check.description || check.name || check.evidence || 'Check'}
                                </li>
                            ))}
                            {serviceChecks[service].length > 3 && (
                                <li style={{ color: '#888' }}>...and {serviceChecks[service].length - 3} more</li>
                            )}
                        </ul>
                    </li>
                ))}
            </ul>
        );

        // Pass/Fail chart
        let pass = 0, fail = 0, other = 0;
        allChecks.forEach(r => {
            if (r.status === 'PASS') pass++;
            else if (r.status === 'FAIL') fail++;
            else other++;
        });
        const pieLabels = ['Pass', 'Fail'];
        const pieData = [pass, fail];
        const pieColors = ['#4CAF50', '#FF5722'];
        if (other > 0) {
            pieLabels.push('Other');
            pieData.push(other);
            pieColors.push('#BDBDBD');
        }
        passFailChart = (
            <div style={{ maxWidth: 220, margin: '0 auto' }}>
                <Pie
                    data={{
                        labels: pieLabels,
                        datasets: [
                            {
                                data: pieData,
                                backgroundColor: pieColors,
                                borderWidth: 2,
                                borderColor: '#23243a',
                            },
                        ],
                    }}
                    options={{
                        responsive: true,
                        plugins: {
                            legend: { position: 'bottom', labels: { color: '#B3E5FC', font: { weight: 'bold' } } },
                            tooltip: {
                                callbacks: {
                                    label: function(context) {
                                        return `${context.label}: ${context.parsed}`;
                                    }
                                }
                            }
                        }
                    }}
                    height={120}
                />
            </div>
        );
    }

    // Handler for clicking a scan in Scan Reports table
    const handleReportScanClick = async (scan) => {
        setSelectedReportScan(scan);
        setReportScanLoading(true);
        setReportScanData(null);
        try {
            const res = await fetch(`http://localhost:5000/scans/results/${scan.name}`);
            const data = await res.json();
            setReportScanData(data);
        } catch {
            setReportScanData(null);
        }
        setReportScanLoading(false);
    };

    const closeReportScanModal = () => {
        setSelectedReportScan(null);
        setReportScanData(null);
        setReportScanLoading(false);
    };

    return (
        <Box sx={{ backgroundColor: '#121212', minHeight: '100vh', color: '#FFFFFF' }}>
            {/* Navbar */}
            <AppBar position="static" sx={{ backgroundColor: '#1F1F2E', boxShadow: '0 4px 10px rgba(0, 0, 0, 0.5)' }}>
                <Toolbar>
                    <Typography
                        variant="h4"
                        sx={{
                            flexGrow: 1,
                            fontWeight: 'bold',
                            fontFamily: 'Roboto, sans-serif',
                            background: 'linear-gradient(90deg, #36A2EB, #4CAF50)',
                            WebkitBackgroundClip: 'text',
                            WebkitTextFillColor: 'transparent',
                            letterSpacing: '2px',
                        }}
                    >
                        awscan
                    </Typography>
                    <Button
                        color="inherit"
                        sx={{ fontWeight: 'bold', marginRight: '15px' }}
                        onClick={() => setShowScanReportsModal(true)}
                    >
                        Scan Reports
                    </Button>
                    <Button color="inherit" sx={{ fontWeight: 'bold', marginRight: '15px' }}>
                        About Us
                    </Button>
                    <Button color="inherit" sx={{ fontWeight: 'bold', marginRight: '15px' }}>
                        Contact
                    </Button>
                    <Button color="inherit" sx={{ fontWeight: 'bold' }}>
                        Help
                    </Button>
                </Toolbar>
            </AppBar>

            {/* Main Content */}
            <Box sx={{ padding: '30px' }}>
                {/* Top Metrics */}
                <Grid container spacing={4} justifyContent="center">
                    <Grid item xs={12} md={4}>
                        <Card
                            sx={{
                                background: 'linear-gradient(135deg, #36A2EB 30%, #1F1F2E 90%)',
                                color: '#FFFFFF',
                                padding: '20px',
                                textAlign: 'center',
                                boxShadow: '0 6px 15px rgba(0, 0, 0, 0.5)',
                                borderRadius: '16px',
                                transition: 'transform 0.3s ease',
                                '&:hover': {
                                    transform: 'scale(1.05)',
                                },
                            }}
                        >
                            <Typography variant="h6">Total Scans</Typography>
                            <Typography variant="h4" sx={{ fontWeight: 'bold' }}>
                                {totalScans}
                            </Typography>
                        </Card>
                    </Grid>
                </Grid>

                {/* Add New Scan Button */}
                <Box sx={{ textAlign: 'center', marginTop: '30px' }}>
                    <Button
                        variant="contained"
                        color="primary"
                        onClick={() => setShowNewScanModal(true)}
                        sx={{
                            backgroundColor: '#4CAF50',
                            padding: '10px 30px',
                            fontSize: '16px',
                            fontWeight: 'bold',
                            borderRadius: '8px',
                            '&:hover': { backgroundColor: '#45A049' },
                        }}
                    >
                        Add New Scan
                    </Button>
                </Box>

                {/* Scan History */}
                <Grid item xs={12} sx={{ marginTop: '30px' }}>
                    <Card
                        sx={{
                            backgroundColor: '#1F1F2E',
                            color: '#FFFFFF',
                            padding: '20px',
                            boxShadow: '0 6px 15px rgba(0, 0, 0, 0.5)',
                            borderRadius: '16px',
                        }}
                    >
                        <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '10px' }}>
                            <Typography variant="h6">Scan History</Typography>
                            <TextField
                                variant="outlined"
                                size="small"
                                placeholder="Search Scans"
                                value={searchTerm}
                                onChange={e => setSearchTerm(e.target.value)}
                                sx={{
                                    backgroundColor: '#FFFFFF',
                                    borderRadius: '4px',
                                    '& .MuiOutlinedInput-root': {
                                        color: '#000000',
                                    },
                                }}
                            />
                        </Box>
                        {/* Pass filteredScans to ScanHistory */}
                        <ScanHistory scans={filteredScans} />
                    </Card>
                </Grid>
            </Box>

            {/* Scan Reports Modal */}
            <Modal
                open={showScanReportsModal}
                onClose={() => setShowScanReportsModal(false)}
                sx={{ display: 'flex', alignItems: 'center', justifyContent: 'center' }}
            >
                <Box
                    sx={{
                        backgroundColor: '#1F1F2E',
                        color: '#FFFFFF',
                        padding: '20px',
                        borderRadius: '8px',
                        width: '80%',
                        maxHeight: '80%',
                        overflowY: 'auto',
                    }}
                >
                    <Typography variant="h5" sx={{ marginBottom: '20px', textAlign: 'center' }}>
                        Scan Reports
                    </Typography>
                    {loadingScans ? (
                        <Typography>Loading...</Typography>
                    ) : (
                        <TableContainer component={Paper} sx={{ backgroundColor: '#2A2A3C' }}>
                            <Table>
                                <TableHead>
                                    <TableRow>
                                        <TableCell sx={{ color: '#FFFFFF' }}>Scan Name</TableCell>
                                        <TableCell sx={{ color: '#FFFFFF' }}>Actions</TableCell>
                                    </TableRow>
                                </TableHead>
                                <TableBody>
                                    {scans.map((scan) => (
                                        <TableRow key={scan.id} hover style={{ cursor: 'pointer' }}>
                                            <TableCell
                                                sx={{ color: '#FFFFFF' }}
                                                onClick={() => handleReportScanClick(scan)}
                                            >
                                                {scan.name}
                                            </TableCell>
                                            <TableCell>
                                                <Button
                                                    variant="contained"
                                                    color="primary"
                                                    href={`http://localhost:4000/scans/results/${scan.name}`}
                                                    target="_blank"
                                                    sx={{
                                                        backgroundColor: '#4CAF50',
                                                        '&:hover': { backgroundColor: '#45A049' },
                                                    }}
                                                >
                                                    Download JSON
                                                </Button>
                                            </TableCell>
                                        </TableRow>
                                    ))}
                                </TableBody>
                            </Table>
                        </TableContainer>
                    )}
                </Box>
            </Modal>

            {/* Scan Report Chart Modal */}
            {selectedReportScan && (
                <Modal
                    open={!!selectedReportScan}
                    onClose={closeReportScanModal}
                    sx={{ display: 'flex', alignItems: 'center', justifyContent: 'center' }}
                >
                    <Box
                        sx={{
                            backgroundColor: '#1F1F2E',
                            color: '#fff',
                            padding: '32px 32px 24px 32px',
                            borderRadius: '16px',
                            boxShadow: '0 8px 32px rgba(0,0,0,0.45)',
                            zIndex: 1000,
                            width: '650px',
                            maxWidth: '95vw',
                            maxHeight: '90vh',
                            overflowY: 'auto',
                        }}
                    >
                        <Typography variant="h6" sx={{ mb: 2, color: '#B3E5FC' }}>
                            {selectedReportScan.name}
                        </Typography>
                        <Typography variant="body2" sx={{ mb: 2 }}>
                            Date: {selectedReportScan.timestamp ? selectedReportScan.timestamp.toLocaleString() : ''}
                        </Typography>
                        {reportScanLoading ? (
                            <Typography>Loading scan details...</Typography>
                        ) : allChecks.length > 0 ? (
                            <>
                                <div style={{ margin: '24px 0' }}>
                                    <Typography variant="subtitle1" sx={{ color: '#36A2EB', mb: 1 }}>Services Checked</Typography>
                                    {servicesChart}
                                    <div style={{ marginTop: 12 }}>{servicesList}</div>
                                </div>
                                <div style={{ margin: '24px 0' }}>
                                    <Typography variant="subtitle1" sx={{ color: '#FFB300', mb: 1 }}>Pass/Fail Distribution</Typography>
                                    {passFailChart}
                                </div>
                            </>
                        ) : (
                            <Typography sx={{ color: '#f44336' }}>Could not load scan details.</Typography>
                        )}
                        <Box sx={{ textAlign: 'right', mt: 3 }}>
                            <Button variant="contained" color="secondary" onClick={closeReportScanModal}>
                                Close
                            </Button>
                        </Box>
                    </Box>
                </Modal>
            )}

            {/* New Scan Modal */}
            {showNewScanModal && <NewScanModal onClose={() => setShowNewScanModal(false)} />}
        </Box>
    );
}

export default DashboardPage;