import React, { useState } from 'react';

function NewScanModal({ onClose }) {
    const [awsCreds, setAwsCreds] = useState({ accessKey: '', secretKey: '', region: '' });

    const handleSubmit = (e) => {
        e.preventDefault();
        alert('New scan started!');
        onClose();
    };

    return (
        <div
            style={{
                position: 'fixed',
                top: '50%',
                left: '50%',
                transform: 'translate(-50%, -50%)',
                backgroundColor: 'white',
                padding: '30px',
                borderRadius: '8px',
                boxShadow: '0 4px 6px rgba(0, 0, 0, 0.1)',
                zIndex: 1000,
                width: '400px',
            }}
        >
            <h2 style={{ marginBottom: '20px', fontSize: '22px', color: '#333' }}>New Scan</h2>
            <form onSubmit={handleSubmit}>
                <input
                    type="text"
                    placeholder="Access Key"
                    value={awsCreds.accessKey}
                    onChange={(e) => setAwsCreds({ ...awsCreds, accessKey: e.target.value })}
                    required
                    style={{
                        display: 'block',
                        marginBottom: '10px',
                        width: '100%',
                        padding: '10px',
                        borderRadius: '4px',
                        border: '1px solid #ccc',
                    }}
                />
                <input
                    type="text"
                    placeholder="Secret Key"
                    value={awsCreds.secretKey}
                    onChange={(e) => setAwsCreds({ ...awsCreds, secretKey: e.target.value })}
                    required
                    style={{
                        display: 'block',
                        marginBottom: '10px',
                        width: '100%',
                        padding: '10px',
                        borderRadius: '4px',
                        border: '1px solid #ccc',
                    }}
                />
                <input
                    type="text"
                    placeholder="Region"
                    value={awsCreds.region}
                    onChange={(e) => setAwsCreds({ ...awsCreds, region: e.target.value })}
                    required
                    style={{
                        display: 'block',
                        marginBottom: '20px',
                        width: '100%',
                        padding: '10px',
                        borderRadius: '4px',
                        border: '1px solid #ccc',
                    }}
                />
                <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                    <button
                        type="submit"
                        style={{
                            backgroundColor: '#4CAF50',
                            color: 'white',
                            border: 'none',
                            padding: '10px 20px',
                            borderRadius: '5px',
                            cursor: 'pointer',
                        }}
                    >
                        Start Scan
                    </button>
                    <button
                        type="button"
                        onClick={onClose}
                        style={{
                            backgroundColor: '#f44336',
                            color: 'white',
                            border: 'none',
                            padding: '10px 20px',
                            borderRadius: '5px',
                            cursor: 'pointer',
                        }}
                    >
                        Cancel
                    </button>
                </div>
            </form>
        </div>
    );
}

export default NewScanModal;