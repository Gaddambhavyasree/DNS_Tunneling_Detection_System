import { Routes, Route } from 'react-router-dom';
import { Sidebar } from './components/Layout';
import { Dashboard } from './pages/Dashboard';
import { UploadPage } from './pages/UploadPage';
import { AnalysisPage } from './pages/AnalysisPage';
import { DetectionPage } from './pages/DetectionPage';
import { AlertsPage } from './pages/AlertsPage';
import { AlertDetailPage } from './pages/AlertDetailPage';
import { DNSQueriesPage } from './pages/DNSQueriesPage';

function App() {
  return (
    <Sidebar>
      <Routes>
        <Route path="/" element={<Dashboard />} />
        <Route path="/upload" element={<UploadPage />} />
        <Route path="/analysis" element={<AnalysisPage />} />
        <Route path="/detection" element={<DetectionPage />} />
        <Route path="/alerts" element={<AlertsPage />} />
        <Route path="/alerts/:alertId" element={<AlertDetailPage />} />
        <Route path="/dns-queries" element={<DNSQueriesPage />} />
      </Routes>
    </Sidebar>
  );
}

export default App;