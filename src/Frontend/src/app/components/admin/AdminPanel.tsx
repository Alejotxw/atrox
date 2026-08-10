import { useState } from 'react';
import { ClipboardList, Users } from 'lucide-react';
import AccessRequestsPanel from './AccessRequestsPanel';
import AccountsPanel from './AccountsPanel';

type AdminSubTab = 'requests' | 'accounts';

export default function AdminPanel() {
  const [subTab, setSubTab] = useState<AdminSubTab>('requests');

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-xl font-bold text-white">Administración</h2>
        <p className="text-sm text-slate-400 mt-1">
          Revisa solicitudes de acceso y gestiona las cuentas de usuario del panel.
        </p>
      </div>

      <div className="flex items-center gap-2 border-b border-slate-800">
        <button
          onClick={() => setSubTab('requests')}
          className={`flex items-center gap-2 px-4 py-2.5 text-sm font-semibold border-b-2 -mb-px transition-all ${
            subTab === 'requests'
              ? 'border-[#7A1C3E] text-white'
              : 'border-transparent text-slate-500 hover:text-slate-300'
          }`}
        >
          <ClipboardList className="w-4 h-4" /> Solicitudes de acceso
        </button>
        <button
          onClick={() => setSubTab('accounts')}
          className={`flex items-center gap-2 px-4 py-2.5 text-sm font-semibold border-b-2 -mb-px transition-all ${
            subTab === 'accounts'
              ? 'border-[#7A1C3E] text-white'
              : 'border-transparent text-slate-500 hover:text-slate-300'
          }`}
        >
          <Users className="w-4 h-4" /> Cuentas
        </button>
      </div>

      {subTab === 'requests' ? <AccessRequestsPanel /> : <AccountsPanel />}
    </div>
  );
}
