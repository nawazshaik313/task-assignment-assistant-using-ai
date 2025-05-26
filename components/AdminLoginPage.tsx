import React, { useState } from 'react';

interface Props {
onLogin: () => void;
}

const AdminLoginPage: React.FC<Props> = ({ onLogin }) => {
const [password, setPassword] = useState('');

const handleSubmit = (e: React.FormEvent) => {
e.preventDefault();
if (password === 'admin123') {
onLogin();
} else {
alert('Incorrect admin password');
}
};

return (
<div className="p-8 max-w-md mx-auto">
<h2 className="text-2xl font-bold mb-4">Admin Login</h2>
<form onSubmit={handleSubmit}>
<input
type="password"
className="border p-2 w-full mb-4"
placeholder="Enter admin password"
value={password}
onChange={e => setPassword(e.target.value)}
/>
<button className="bg-blue-600 text-white px-4 py-2 rounded" type="submit">
Login
</button>
</form>
</div>
);
};

export default AdminLoginPage;

