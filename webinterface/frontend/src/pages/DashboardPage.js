import React, { useState } from 'react';
import { Box, Grid, Card, Typography, Button, TextField } from '@mui/material';
import { Bar, Line, Doughnut } from 'react-chartjs-2';
import { Chart as ChartJS, CategoryScale, LinearScale, BarElement, LineElement, Title, Tooltip, Legend, ArcElement, PointElement } from 'chart.js';
import NewScanModal from '../components/NewScanModal';
import ScanHistory from '../components/ScanHistory';
import DashboardIcon from '@mui/icons-material/Dashboard';
import HistoryIcon from '@mui/icons-material/History';
import ReportIcon from '@mui/icons-material/Assessment';

ChartJS.register(CategoryScale, LinearScale, BarElement, LineElement, ArcElement, PointElement, Title, Tooltip, Legend);

function DashboardPage() {
    const [showNewScanModal, setShowNewScanModal] = useState(false);

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

    return (
        <Box sx={{ display: 'flex', backgroundColor: '#1E1E2F', minHeight: '100vh', color: '#FFFFFF' }}>
            {/* Sidebar */}
            <Box
                sx={{
                    width: '250px',
                    backgroundColor: '#2A2A40',
                    padding: '20px',
                    display: 'flex',
                    flexDirection: 'column',
                    gap: '20px',
                }}
            >
                <Typography variant="h5" sx={{ fontWeight: 'bold', color: '#FFFFFF', textAlign: 'center' }}>
                    AWS Dashboard
                </Typography>
                <Button startIcon={<DashboardIcon />} variant="text" sx={{ color: '#FFFFFF', justifyContent: 'flex-start' }}>
                    Dashboard
                </Button>
                <Button startIcon={<HistoryIcon />} variant="text" sx={{ color: '#FFFFFF', justifyContent: 'flex-start' }}>
                    Manage Scans
                </Button>
                <Button startIcon={<ReportIcon />} variant="text" sx={{ color: '#FFFFFF', justifyContent: 'flex-start' }}>
                    Reports
                </Button>
            </Box>

            {/* Main Content */}
            <Box sx={{ flex: 1, padding: '20px', textAlign: 'center' }}>
                {/* Top Metrics */}
                <Grid container spacing={3} justifyContent="center">
                    {['Total Scans', 'High Severity Issues', 'Medium Severity Issues', 'Low Severity Issues'].map((title, index) => (
                        <Grid item xs={12} md={3} key={index}>
                            <Card
                                sx={{
                                    background: `linear-gradient(135deg, ${['#4CAF50', '#FF5722', '#FFC107', '#36A2EB'][index]} 30%, #2A2A40 90%)`,
                                    color: '#FFFFFF',
                                    padding: '20px',
                                    textAlign: 'center',
                                    boxShadow: '0 4px 10px rgba(0, 0, 0, 0.3)',
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
                <Grid container spacing={3} sx={{ marginTop: '20px' }} justifyContent="center">
                    <Grid item xs={12} md={6}>
                        <Card sx={{ backgroundColor: '#2A2A40', color: '#FFFFFF', padding: '20px', boxShadow: '0 4px 10px rgba(0, 0, 0, 0.3)' }}>
                            <Box sx={{ marginBottom: '10px' }}>
                                <Typography variant="h6">Scan Severity Overview</Typography>
                            </Box>
                            <Bar data={barChartData} />
                        </Card>
                    </Grid>
                    <Grid item xs={12} md={6}>
                        <Card sx={{ backgroundColor: '#2A2A40', color: '#FFFFFF', padding: '20px', boxShadow: '0 4px 10px rgba(0, 0, 0, 0.3)' }}>
                            <Box sx={{ marginBottom: '10px' }}>
                                <Typography variant="h6">Scans Over Time</Typography>
                            </Box>
                            <Line data={lineChartData} />
                        </Card>
                    </Grid>
                    <Grid item xs={12} md={6}>
                        <Card sx={{ backgroundColor: '#2A2A40', color: '#FFFFFF', padding: '20px', boxShadow: '0 4px 10px rgba(0, 0, 0, 0.3)' }}>
                            <Box sx={{ marginBottom: '10px' }}>
                                <Typography variant="h6">Severity Distribution</Typography>
                            </Box>
                            <Doughnut data={doughnutChartData} />
                        </Card>
                    </Grid>
                </Grid>

                {/* Add New Scan Button */}
                <Button
                    variant="contained"
                    color="primary"
                    onClick={() => setShowNewScanModal(true)}
                    sx={{ marginTop: '20px', marginBottom: '20px' }}
                >
                    Add New Scan
                </Button>

                {/* Scan History */}
                <Grid item xs={12}>
                    <Card sx={{ backgroundColor: '#2A2A40', color: '#FFFFFF', padding: '20px', boxShadow: '0 4px 10px rgba(0, 0, 0, 0.3)' }}>
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

            {/* New Scan Modal */}
            {showNewScanModal && <NewScanModal onClose={() => setShowNewScanModal(false)} />}
        </Box>
    );
}

export default DashboardPage;