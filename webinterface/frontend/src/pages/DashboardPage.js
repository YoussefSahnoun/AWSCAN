import React, { useState } from 'react';
import { Box, Grid, Card, CardContent, Typography, Button, Divider } from '@mui/material';
import { Bar, Line, Doughnut } from 'react-chartjs-2';
import { Chart as ChartJS, CategoryScale, LinearScale, BarElement, LineElement, Title, Tooltip, Legend, ArcElement, PointElement } from 'chart.js';
import NewScanModal from '../components/NewScanModal';
import ScanHistory from '../components/ScanHistory';

ChartJS.register(CategoryScale, LinearScale, BarElement, LineElement, ArcElement, PointElement, Title, Tooltip, Legend);

function DashboardPage() {
    const [showNewScanModal, setShowNewScanModal] = useState(false);

    // Example data for the bar chart
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
                <Typography variant="h5" sx={{ fontWeight: 'bold', color: '#FFFFFF' }}>
                    AWS Dashboard
                </Typography>
                <Button variant="text" sx={{ color: '#FFFFFF', justifyContent: 'flex-start' }}>
                    Dashboard
                </Button>
                <Button variant="text" sx={{ color: '#FFFFFF', justifyContent: 'flex-start' }}>
                    Manage Scans
                </Button>
                <Button variant="text" sx={{ color: '#FFFFFF', justifyContent: 'flex-start' }}>
                    Reports
                </Button>
            </Box>

            {/* Main Content */}
            <Box sx={{ flex: 1, padding: '20px' }}>
                {/* Top Metrics */}
                <Grid container spacing={3}>
                    <Grid item xs={12} md={3}>
                        <Card sx={{ backgroundColor: '#2A2A40', color: '#FFFFFF', padding: '20px' }}>
                            <Typography variant="h6">Total Scans</Typography>
                            <Typography variant="h4" sx={{ fontWeight: 'bold', color: '#4CAF50' }}>
                                25
                            </Typography>
                        </Card>
                    </Grid>
                    <Grid item xs={12} md={3}>
                        <Card sx={{ backgroundColor: '#2A2A40', color: '#FFFFFF', padding: '20px' }}>
                            <Typography variant="h6">High Severity Issues</Typography>
                            <Typography variant="h4" sx={{ fontWeight: 'bold', color: '#FF5722' }}>
                                15
                            </Typography>
                        </Card>
                    </Grid>
                    <Grid item xs={12} md={3}>
                        <Card sx={{ backgroundColor: '#2A2A40', color: '#FFFFFF', padding: '20px' }}>
                            <Typography variant="h6">Medium Severity Issues</Typography>
                            <Typography variant="h4" sx={{ fontWeight: 'bold', color: '#FFC107' }}>
                                30
                            </Typography>
                        </Card>
                    </Grid>
                    <Grid item xs={12} md={3}>
                        <Card sx={{ backgroundColor: '#2A2A40', color: '#FFFFFF', padding: '20px' }}>
                            <Typography variant="h6">Low Severity Issues</Typography>
                            <Typography variant="h4" sx={{ fontWeight: 'bold', color: '#36A2EB' }}>
                                55
                            </Typography>
                        </Card>
                    </Grid>
                </Grid>

                {/* Charts Section */}
                <Grid container spacing={3} sx={{ marginTop: '20px' }}>
                    <Grid item xs={12} md={6}>
                        <Card sx={{ backgroundColor: '#2A2A40', color: '#FFFFFF', padding: '20px' }}>
                            <Typography variant="h6" sx={{ marginBottom: '10px' }}>
                                Scan Severity Overview
                            </Typography>
                            <Bar data={barChartData} />
                        </Card>
                    </Grid>
                    <Grid item xs={12} md={6}>
                        <Card sx={{ backgroundColor: '#2A2A40', color: '#FFFFFF', padding: '20px' }}>
                            <Typography variant="h6" sx={{ marginBottom: '10px' }}>
                                Scans Over Time
                            </Typography>
                            <Line data={lineChartData} />
                        </Card>
                    </Grid>
                    <Grid item xs={12} md={6}>
                        <Card sx={{ backgroundColor: '#2A2A40', color: '#FFFFFF', padding: '20px' }}>
                            <Typography variant="h6" sx={{ marginBottom: '10px' }}>
                                Severity Distribution
                            </Typography>
                            <Doughnut data={doughnutChartData} />
                        </Card>
                    </Grid>
                </Grid>

                {/* Scan History */}
                <Grid item xs={12} sx={{ marginTop: '20px' }}>
                    <Card sx={{ backgroundColor: '#2A2A40', color: '#FFFFFF', padding: '20px' }}>
                        <Typography variant="h6" sx={{ marginBottom: '10px' }}>
                            Scan History
                        </Typography>
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