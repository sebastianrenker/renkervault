import React from 'react';
import ReactDOM from 'react-dom/client';
import App from './ui/App';
import './styles.css';

// Standard-Theme setzen, bevor React rendert (kein Flash)
if (!document.documentElement.dataset.theme) {
  document.documentElement.dataset.theme = 'default';
}

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
);
