import React, { useState } from 'react';
import { Bar, Pie } from 'react-chartjs-2';
import { Chart as ChartJS, CategoryScale, LinearScale, BarElement, ArcElement, Tooltip, Legend } from 'chart.js';

ChartJS.register(CategoryScale, LinearScale, BarElement, ArcElement, Tooltip, Legend);

function ScanHistory({ scans = [] }) {
    const [selectedScan, setSelectedScan] = useState(null);
    const [scanData, setScanData] = useState(null);
    const [loading, setLoading] = useState(false);

    const handleScanClick = async (scan) => {
        setSelectedScan(scan);
        setLoading(true);
        try {
            const res = await fetch(`http://localhost:5000/scans/results/${scan.name}`);
            const data = await res.json();
            setScanData(data);
        } catch {
            setScanData(null);
        }
        setLoading(false);
    };

    const closeModal = () => {
        setSelectedScan(null);
        setScanData(null);
        setLoading(false);
    };

    // Prepare chart data if scanData is loaded
    let servicesChart = null;
    let passFailChart = null;
    let servicesList = null;

    // Flatten raw_results if present
    let allChecks = [];
    if (scanData && Array.isArray(scanData.raw_results)) {
        allChecks = scanData.raw_results.flat();
    }

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

    return (
        <div>
            <ul style={{ listStyle: 'none', padding: 0 }}>
                {scans.map((scan) => (
                    <li
                        key={scan.id}
                        style={{
                            marginBottom: '10px',
                            padding: '10px',
                            backgroundColor: '#23243a',
                            borderRadius: '4px',
                            cursor: 'pointer',
                            color: '#fff',
                        }}
                        onClick={() => handleScanClick(scan)}
                    >
                        <strong>{scan.name}</strong>
                        <span style={{ marginLeft: 10, color: '#B3E5FC' }}>
                            {scan.timestamp ? scan.timestamp.toLocaleString() : ''}
                        </span>
                    </li>
                ))}
            </ul>

            {/* Modal for Scan Details with Charts */}
            {selectedScan && (
                <div
                    style={{
                        position: 'fixed',
                        top: '50%',
                        left: '50%',
                        transform: 'translate(-50%, -50%)',
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
                    <h2 style={{ marginBottom: '10px', fontSize: '22px', color: '#B3E5FC' }}>{selectedScan.name}</h2>
                    <p><strong>Date:</strong> {selectedScan.timestamp ? selectedScan.timestamp.toLocaleString() : ''}</p>
                    {loading ? (
                        <p>Loading scan details...</p>
                    ) : allChecks.length > 0 ? (
                        <>
                            <div style={{ margin: '24px 0' }}>
                                <h4 style={{ color: '#36A2EB', marginBottom: 8 }}>Services Checked</h4>
                                {servicesChart}
                                <div style={{ marginTop: 12 }}>{servicesList}</div>
                            </div>
                            <div style={{ margin: '24px 0' }}>
                                <h4 style={{ color: '#FFB300', marginBottom: 8 }}>Pass/Fail Distribution</h4>
                                {passFailChart}
                            </div>
                        </>
                    ) : (
                        <p style={{ color: '#f44336' }}>Could not load scan details.</p>
                    )}
                    <button
                        onClick={closeModal}
                        style={{
                            marginTop: '20px',
                            backgroundColor: '#f44336',
                            color: 'white',
                            border: 'none',
                            padding: '10px 20px',
                            borderRadius: '5px',
                            cursor: 'pointer',
                        }}
                    >
                        Close
                    </button>
                </div>
            )}

            {/* Modal Background */}
            {selectedScan && (
                <div
                    onClick={closeModal}
                    style={{
                        position: 'fixed',
                        top: 0,
                        left: 0,
                        width: '100%',
                        height: '100%',
                        backgroundColor: 'rgba(0, 0, 0, 0.5)',
                        zIndex: 999,
                    }}
                ></div>
            )}
        </div>
    );
}

export default ScanHistory;