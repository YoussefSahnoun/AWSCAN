import React, { useState } from 'react';
import { Box, TextField, Button, CircularProgress, Typography } from '@mui/material';

function NewScanModal({ onClose }) {
    const [awsCreds, setAwsCreds] = useState({
        accessKey: '',
        secretKey: '',
        sessionToken: '',
        region: '',
    });
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState('');
    const [success, setSuccess] = useState('');

    const handleSubmit = async (e) => {
        e.preventDefault();
        setLoading(true);
        setError('');
        setSuccess('');

        try {
            const response = await fetch('http://localhost:5000/scans/run', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    access_key: awsCreds.accessKey,
                    secret_key: awsCreds.secretKey,
                    session_token: awsCreds.sessionToken,
                    region: awsCreds.region,
                }),
            });

            if (!response.ok) {
                throw new Error('Failed to start scan');
            }

            setSuccess('Scan started successfully!');
            setTimeout(() => {
                setLoading(false);
                onClose();
            }, 1500);
        } catch (err) {
            setError(err.message);
            setLoading(false);
        }
    };

    return (
        <Box
            sx={{
                position: 'fixed',
                top: '50%',
                left: '50%',
                transform: 'translate(-50%, -50%)',
                backgroundColor: '#2A2A40',
                padding: '40px',
                borderRadius: '12px',
                boxShadow: '0 8px 16px rgba(0, 0, 0, 0.2)',
                zIndex: 1000,
                width: '600px',
                color: '#FFFFFF',
            }}
        >
            <Typography variant="h4" sx={{ marginBottom: '20px', textAlign: 'center' }}>
                Start a New Scan
            </Typography>
            <form onSubmit={handleSubmit}>
                <TextField
                    label="AWS Access Key ID"
                    variant="outlined"
                    fullWidth
                    required
                    value={awsCreds.accessKey}
                    onChange={(e) => setAwsCreds({ ...awsCreds, accessKey: e.target.value })}
                    sx={{ marginBottom: '20px', backgroundColor: '#FFFFFF', borderRadius: '4px' }}
                />
                <TextField
                    label="AWS Secret Access Key"
                    variant="outlined"
                    fullWidth
                    required
                    value={awsCreds.secretKey}
                    onChange={(e) => setAwsCreds({ ...awsCreds, secretKey: e.target.value })}
                    sx={{ marginBottom: '20px', backgroundColor: '#FFFFFF', borderRadius: '4px' }}
                />
                <TextField
                    label="AWS Session Token"
                    variant="outlined"
                    fullWidth
                    value={awsCreds.sessionToken}
                    onChange={(e) => setAwsCreds({ ...awsCreds, sessionToken: e.target.value })}
                    sx={{ marginBottom: '20px', backgroundColor: '#FFFFFF', borderRadius: '4px' }}
                />
                <TextField
                    label="Region"
                    variant="outlined"
                    fullWidth
                    required
                    value={awsCreds.region}
                    onChange={(e) => setAwsCreds({ ...awsCreds, region: e.target.value })}
                    sx={{ marginBottom: '20px', backgroundColor: '#FFFFFF', borderRadius: '4px' }}
                />
                <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <Button
                        type="button"
                        variant="outlined"
                        color="secondary"
                        onClick={onClose}
                        sx={{ width: '48%' }}
                        disabled={loading}
                    >
                        Cancel
                    </Button>
                    <Button
                        type="submit"
                        variant="contained"
                        color="primary"
                        disabled={loading}
                        sx={{ width: '48%' }}
                    >
                        {loading ? 'Starting...' : 'Start Scan'}
                    </Button>
                </Box>
                {loading && (
                    <Box sx={{ display: 'flex', justifyContent: 'center', marginTop: '20px' }}>
                        <CircularProgress />
                    </Box>
                )}
                {error && (
                    <Typography sx={{ color: 'red', mt: 2, textAlign: 'center' }}>{error}</Typography>
                )}
                {success && (
                    <Typography sx={{ color: 'lightgreen', mt: 2, textAlign: 'center' }}>{success}</Typography>
                )}
            </form>
        </Box>
    );
}

export default NewScanModal;