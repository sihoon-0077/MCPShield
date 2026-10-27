import { OperationsConsole } from "../../../components/operations-console";
import { LanguageSwitcher } from "../../../components/site/i18n";
import { Sidebar } from "../../../components/site/workspace";
import "./console.css";

// The console keeps its own markup (and the page's only <main>) inside the workspace shell.
// data-raw keeps API states such as COMPLETED or FAILED out of the KR/EN text translator.
export default function Page() {
  return (
    <div className="workspace">
      <Sidebar active="Settings" />
      <div className="ws-main">
        <header className="ws-topbar"><div className="ws-breadcrumb"><span>MCPShield</span><b>/</b> Settings <b>/</b> 운영 콘솔</div><LanguageSwitcher /></header>
        <div className="ws-content" data-raw><OperationsConsole /></div>
      </div>
    </div>
  );
}
