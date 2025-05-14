import React, { useState } from 'react';
import { AppBar, Toolbar, Typography, Button, Box, Grid, Card, Modal, Table, TableBody, TableCell, TableContainer, TableHead, TableRow, Paper } from '@mui/material';
import { Bar, Line, Doughnut } from 'react-chartjs-2';
import { Chart as ChartJS, CategoryScale, LinearScale, BarElement, LineElement, Title, Tooltip, Legend, ArcElement, PointElement } from 'chart.js';
import NewScanModal from '../components/NewScanModal';
import ScanHistory from '../components/ScanHistory';
import { TextField } from '@mui/material';
import jsPDF from 'jspdf';

ChartJS.register(CategoryScale, LinearScale, BarElement, LineElement, ArcElement, PointElement, Title, Tooltip, Legend);

function DashboardPage() {
    const [showNewScanModal, setShowNewScanModal] = useState(false);
    const [showScanReportsModal, setShowScanReportsModal] = useState(false);

    const barChartData = {
        labels: ['Scan #1', 'Scan #2', 'Scan #3', 'Scan #4', 'Scan #5'],
        datasets: [
            {
                label: 'High Severity Issues',
                data: [5, 3, 8, 2, 6],
                backgroundColor: 'rgba(255, 99, 132, 0.5)',
            },
            {
                label: 'Medium Severity Issues',
                data: [10, 7, 5, 8, 4],
                backgroundColor: 'rgba(54, 162, 235, 0.5)',
            },
        ],
    };

    const lineChartData = {
        labels: ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun'],
        datasets: [
            {
                label: 'Scans Completed',
                data: [10, 15, 20, 25, 30, 35],
                borderColor: 'rgba(75, 192, 192, 1)',
                backgroundColor: 'rgba(75, 192, 192, 0.2)',
                tension: 0.4,
            },
        ],
    };

    const doughnutChartData = {
        labels: ['High Severity', 'Medium Severity', 'Low Severity'],
        datasets: [
            {
                data: [15, 30, 55],
                backgroundColor: ['#FF6384', '#36A2EB', '#FFCE56'],
            },
        ],
    };

    const scans = [
        { id: 1, name: 'Scan #1', high: 5, medium: 10, low: 15 },
        { id: 2, name: 'Scan #2', high: 3, medium: 7, low: 30 },
        { id: 3, name: 'Scan #3', high: 8, medium: 5, low: 55 },
    ];

    const generatePDF = (scan) => {
        const doc = new jsPDF();

        // Add title
        doc.setFontSize(18);
        doc.text(`Scan Report: ${scan.name}`, 10, 10);

        // Add content
        doc.setFontSize(12);
        doc.text(`High Severity Issues: ${scan.high}`, 10, 20);
        doc.text(`Medium Severity Issues: ${scan.medium}`, 10, 30);
        doc.text(`Low Severity Issues: ${scan.low}`, 10, 40);

        // Save the PDF
        doc.save(`${scan.name}_Report.pdf`);
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
                    {['Total Scans', 'High Severity Issues', 'Medium Severity Issues', 'Low Severity Issues'].map((title, index) => (
                        <Grid item xs={12} md={3} key={index}>
                            <Card
                                sx={{
                                    background: `linear-gradient(135deg, ${['#4CAF50', '#FF5722', '#FFC107', '#36A2EB'][index]} 30%, #1F1F2E 90%)`,
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
                                <Typography variant="h6">{title}</Typography>
                                <Typography variant="h4" sx={{ fontWeight: 'bold' }}>
                                    {[25, 15, 30, 55][index]}
                                </Typography>
                            </Card>
                        </Grid>
                    ))}
                </Grid>

                {/* Charts Section */}
                <Grid container spacing={4} sx={{ marginTop: '30px' }} justifyContent="center">
                    <Grid item xs={12} md={6}>
                        <Card
                            sx={{
                                backgroundColor: '#1F1F2E',
                                color: '#FFFFFF',
                                padding: '20px',
                                boxShadow: '0 6px 15px rgba(0, 0, 0, 0.5)',
                                borderRadius: '16px',
                            }}
                        >
                            <Box sx={{ marginBottom: '10px' }}>
                                <Typography variant="h6">Scan Severity Overview</Typography>
                            </Box>
                            <Bar data={barChartData} />
                        </Card>
                    </Grid>
                    <Grid item xs={12} md={6}>
                        <Card
                            sx={{
                                backgroundColor: '#1F1F2E',
                                color: '#FFFFFF',
                                padding: '20px',
                                boxShadow: '0 6px 15px rgba(0, 0, 0, 0.5)',
                                borderRadius: '16px',
                            }}
                        >
                            <Box sx={{ marginBottom: '10px' }}>
                                <Typography variant="h6">Scans Over Time</Typography>
                            </Box>
                            <Line data={lineChartData} />
                        </Card>
                    </Grid>
                    <Grid item xs={12} md={6}>
                        <Card
                            sx={{
                                backgroundColor: '#1F1F2E',
                                color: '#FFFFFF',
                                padding: '20px',
                                boxShadow: '0 6px 15px rgba(0, 0, 0, 0.5)',
                                borderRadius: '16px',
                            }}
                        >
                            <Box sx={{ marginBottom: '10px' }}>
                                <Typography variant="h6">Severity Distribution</Typography>
                            </Box>
                            <Doughnut data={doughnutChartData} />
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
                                sx={{
                                    backgroundColor: '#FFFFFF',
                                    borderRadius: '4px',
                                    '& .MuiOutlinedInput-root': {
                                        color: '#000000',
                                    },
                                }}
                            />
                        </Box>
                        <ScanHistory />
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
                    <TableContainer component={Paper} sx={{ backgroundColor: '#2A2A3C' }}>
                        <Table>
                            <TableHead>
                                <TableRow>
                                    <TableCell sx={{ color: '#FFFFFF' }}>Scan Name</TableCell>
                                    <TableCell sx={{ color: '#FFFFFF' }}>High Severity</TableCell>
                                    <TableCell sx={{ color: '#FFFFFF' }}>Medium Severity</TableCell>
                                    <TableCell sx={{ color: '#FFFFFF' }}>Low Severity</TableCell>
                                    <TableCell sx={{ color: '#FFFFFF' }}>Actions</TableCell>
                                </TableRow>
                            </TableHead>
                            <TableBody>
                                {scans.map((scan) => (
                                    <TableRow key={scan.id}>
                                        <TableCell sx={{ color: '#FFFFFF' }}>{scan.name}</TableCell>
                                        <TableCell sx={{ color: '#FFFFFF' }}>{scan.high}</TableCell>
                                        <TableCell sx={{ color: '#FFFFFF' }}>{scan.medium}</TableCell>
                                        <TableCell sx={{ color: '#FFFFFF' }}>{scan.low}</TableCell>
                                        <TableCell>
                                            <Button
                                                variant="contained"
                                                color="primary"
                                                onClick={() => generatePDF(scan)}
                                                sx={{
                                                    backgroundColor: '#4CAF50',
                                                    '&:hover': { backgroundColor: '#45A049' },
                                                }}
                                            >
                                                Download
                                            </Button>
                                        </TableCell>
                                    </TableRow>
                                ))}
                            </TableBody>
                        </Table>
                    </TableContainer>
                </Box>
            </Modal>

            {/* New Scan Modal */}
            {showNewScanModal && <NewScanModal onClose={() => setShowNewScanModal(false)} />}
        </Box>
    );
}

export default DashboardPage;