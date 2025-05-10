import React, { useState } from 'react';
import { AppBar, Toolbar, Typography, Button, Box, Grid, Card, TextField, IconButton } from '@mui/material';
import { Bar, Line, Doughnut } from 'react-chartjs-2';
import { Chart as ChartJS, CategoryScale, LinearScale, BarElement, LineElement, Title, Tooltip, Legend, ArcElement, PointElement } from 'chart.js';
import NewScanModal from '../components/NewScanModal';
import ScanHistory from '../components/ScanHistory';
import NotificationsIcon from '@mui/icons-material/Notifications';
import AccountCircleIcon from '@mui/icons-material/AccountCircle';

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
                    <Button color="inherit" sx={{ fontWeight: 'bold', marginRight: '15px' }}>
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

            {/* New Scan Modal */}
            {showNewScanModal && <NewScanModal onClose={() => setShowNewScanModal(false)} />}
        </Box>
    );
}

export default DashboardPage;