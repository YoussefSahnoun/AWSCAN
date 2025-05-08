import React, { useState } from 'react';

function ScanHistory() {
    const [selectedScan, setSelectedScan] = useState(null);

    const scans = [
        { id: 1, name: 'Scan #1', date: '2025-05-01', severity: 'High', findings: ['Issue 1', 'Issue 2', 'Issue 3'] },
        { id: 2, name: 'Scan #2', date: '2025-05-03', severity: 'Medium', findings: ['Issue 4', 'Issue 5'] },
        { id: 3, name: 'Scan #3', date: '2025-05-05', severity: 'Low', findings: ['Issue 6'] },
    ];

    const handleScanClick = (scan) => {
        setSelectedScan(scan);
    };

    const closeModal = () => {
        setSelectedScan(null);
    };

    return (
        <div>
            <ul style={{ listStyle: 'none', padding: 0 }}>
                {scans.map((scan) => (
                    <li
                        key={scan.id}
                        style={{
                            marginBottom: '10px',
                            padding: '10px',
                            backgroundColor: '#f9f9f9',
                            borderRadius: '4px',
                            cursor: 'pointer',
                        }}
                        onClick={() => handleScanClick(scan)}
                    >
                        <strong>{scan.name}:</strong> Completed on {scan.date}
                    </li>
                ))}
            </ul>

            {/* Modal for Scan Details */}
            {selectedScan && (
                <div
                    style={{
                        position: 'fixed',
                        top: '50%',
                        left: '50%',
                        transform: 'translate(-50%, -50%)',
                        backgroundColor: 'white',
                        padding: '20px',
                        borderRadius: '8px',
                        boxShadow: '0 4px 6px rgba(0, 0, 0, 0.1)',
                        zIndex: 1000,
                        width: '400px',
                    }}
                >
                    <h2 style={{ marginBottom: '10px', fontSize: '22px', color: '#333' }}>{selectedScan.name}</h2>
                    <p><strong>Date:</strong> {selectedScan.date}</p>
                    <p><strong>Severity:</strong> {selectedScan.severity}</p>
                    <h3 style={{ marginTop: '20px', fontSize: '18px', color: '#333' }}>Findings:</h3>
                    <ul>
                        {selectedScan.findings.map((finding, index) => (
                            <li key={index} style={{ marginBottom: '5px' }}>
                                {finding}
                            </li>
                        ))}
                    </ul>
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