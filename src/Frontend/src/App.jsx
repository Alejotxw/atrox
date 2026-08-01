import ScheduleManager from './components/ScheduleManager';
import './App.css';

function App() {
  return (
    <div className="app-container">
      <nav className="navbar">
        <div className="navbar-brand">
          <span className="brand-logo">🛡️</span> ATROX CyberSecurity
        </div>
      </nav>

      <main className="main-content">
        <ScheduleManager />
      </main>
    </div>
  );
}

export default App;
