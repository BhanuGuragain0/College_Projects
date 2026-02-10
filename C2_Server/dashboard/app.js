// dashboard/app.js
import React, { useEffect, useState } from 'react';
import axios from 'axios';

function Dashboard() {
    const [bots, setBots] = useState([]);
    const [tasks, setTasks] = useState([]);

    useEffect(() => {
        axios.get('/')
            .then(response => {
                setBots(response.data.bots);
                setTasks(response.data.tasks);
            });
    }, []);

    return (
        <div>
            <h1>C2 Server Dashboard</h1>
            <h2>Bots</h2>
            <pre>{JSON.stringify(bots, null, 2)}</pre>
            <h2>Tasks</h2>
            <pre>{JSON.stringify(tasks, null, 2)}</pre>
        </div>
    );
}

export default Dashboard;
