import { ReactNode } from 'react';
import { Link, useLocation } from 'react-router-dom';
import { Shield, Upload, BarChart2, LayoutDashboard, ShieldAlert, Bell, Database, Search } from 'lucide-react';

const navigation = [
  { name: 'Dashboard', href: '/', icon: LayoutDashboard },
  { name: 'Upload PCAP', href: '/upload', icon: Upload },
  { name: 'Analysis', href: '/analysis', icon: BarChart2 },
  { name: 'Detection', href: '/detection', icon: ShieldAlert },
  { name: 'Alerts', href: '/alerts', icon: Bell },
  { name: 'DNS Queries', href: '/dns-queries', icon: Database },
];

export function Sidebar({ children }: { children: ReactNode }) {
  const location = useLocation();
  
  return (
    <div className="flex h-screen bg-dark-bg">
      <aside className="w-64 bg-dark-card border-r border-dark-border flex flex-col">
        <div className="p-6 border-b border-dark-border">
          <Link to="/" className="flex items-center gap-3">
            <Shield className="w-8 h-8 text-primary-500" />
            <span className="text-xl font-bold text-white">DNS Detector</span>
          </Link>
          <p className="text-xs text-slate-500 mt-2">Rule-based Detection</p>
        </div>
        
        <nav className="flex-1 p-4 space-y-1">
          {navigation.map((item) => {
            const isActive = location.pathname === item.href || (item.href !== '/' && location.pathname.startsWith(item.href));
            return (
              <Link
                key={item.name}
                to={item.href}
                className={`flex items-center gap-3 px-3 py-2 rounded-lg text-sm font-medium transition-colors ${
                  isActive
                    ? 'bg-primary-500/20 text-primary-400'
                    : 'text-slate-400 hover:text-white hover:bg-slate-800/50'
                }`}
              >
                <item.icon className="w-5 h-5" />
                {item.name}
              </Link>
            );
          })}
        </nav>
        
        <div className="p-4 border-t border-dark-border">
          <div className="text-xs text-slate-500">
            <p className="font-medium mb-1">System Status</p>
            <div className="flex items-center gap-2 text-slate-400">
              <span className="w-2 h-2 bg-green-500 rounded-full" />
              <span>Backend Connected</span>
            </div>
          </div>
        </div>
      </aside>
      
      <main className="flex-1 overflow-auto">
        {children}
      </main>
    </div>
  );
}