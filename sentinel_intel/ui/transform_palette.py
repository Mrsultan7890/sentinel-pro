"""Transform Palette v2.0 - 30+ Transforms + Auto-Chaining"""
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLineEdit, QPushButton,
    QListWidget, QListWidgetItem, QLabel, QSpinBox, QComboBox, QTabWidget, QProgressBar
)
from PyQt6.QtCore import Qt, pyqtSignal, QTimer, QThread
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

class TransformPalette(QWidget):
    def __init__(self, main_window):
        super().__init__()
        self.main_window = main_window
        layout = QVBoxLayout(self)
        
        # Search box
        self.search_box = QLineEdit()
        self.search_box.setPlaceholderText("Search transforms...")
        self.search_box.textChanged.connect(self._filter_transforms)
        layout.addWidget(self.search_box)
        
        # Transform categories
        self.tabs = QTabWidget()
        
        # Email Transforms
        email_tab = self._create_transform_tab([
            ('Full Investigation', 'email_investigate'),
            ('To Breaches', 'email_to_breaches'),
            ('To Profiles', 'email_to_profiles'),
            ('🌍 To Domains', 'email_to_domains'),
            ('To Usernames', 'email_to_usernames'),
            ('To Phones', 'email_to_phones'),
            ('📝 To Names', 'email_to_names'),
            ('To Social Media', 'email_to_social_media')
        ])
        self.tabs.addTab(email_tab, "Email")
        
        # Phone Transforms
        phone_tab = self._create_transform_tab([
            ('Full Investigation', 'phone_investigate'),
            ('📡 To Carrier', 'phone_to_carrier'),
            ('To Location', 'phone_to_location'),
            ('💬 To Messaging Apps', 'phone_to_messaging_apps'),
            ('📝 To Names', 'phone_to_names'),
            ('To Emails', 'phone_to_emails'),
            ('To Profiles', 'phone_to_profiles')
        ])
        self.tabs.addTab(phone_tab, "Phone")
        
        # IP Transforms
        ip_tab = self._create_transform_tab([
            ('Full Investigation', 'ip_investigate'),
            ('To Geolocation', 'ip_to_geolocation'),
            ('🔌 To Ports', 'ip_to_ports'),
            ('To Vulnerabilities', 'ip_to_vulns'),
            ('🌍 To Domains', 'ip_to_domains'),
            ('🔢 To ASN', 'ip_to_asn'),
            ('To Threat Intel', 'ip_to_threat_intel')
        ])
        self.tabs.addTab(ip_tab, "IP")
        
        # Domain Transforms
        domain_tab = self._create_transform_tab([
            ('Full Investigation', 'domain_investigate'),
            ('To IPs', 'domain_to_ips'),
            ('🌳 To Subdomains', 'domain_to_subdomains'),
            ('📋 To WHOIS', 'domain_to_whois'),
            ('⚙️ To Tech Stack', 'domain_to_tech_stack'),
            ('To Certificates', 'domain_to_certificates'),
            ('🖥️ To Nameservers', 'domain_to_nameservers')
        ])
        self.tabs.addTab(domain_tab, "🌍 Domain")
        
        # Person Transforms
        person_tab = self._create_transform_tab([
            ('Full Investigation', 'person_investigate'),
            ('To Emails', 'person_to_emails'),
            ('To Phones', 'person_to_phones'),
            ('To Usernames', 'person_to_usernames'),
            ('To Profiles', 'person_to_profiles'),
            ('To Addresses', 'person_to_addresses'),
            ('💼 To Jobs', 'person_to_jobs')
        ])
        self.tabs.addTab(person_tab, "Person")
        
        # Username Transforms
        username_tab = self._create_transform_tab([
            ('Full Investigation', 'username_investigate'),
            ('To Platforms', 'username_to_platforms'),
            ('To Profile Links', 'username_to_profile_links')
        ])
        self.tabs.addTab(username_tab, "Username")
        
        # Hash Transforms
        hash_tab = self._create_transform_tab([
            ('Full Investigation', 'hash_investigate'),
            ('To Malware Families', 'hash_to_malware_families'),
            ('To Threat Names', 'hash_to_threat_names'),
            ('📄 To File Info', 'hash_to_file_info')
        ])
        self.tabs.addTab(hash_tab, "Hash")
        
        # Crypto Transforms
        crypto_tab = self._create_transform_tab([
            ('Full Investigation', 'crypto_investigate'),
            ('💸 To Transactions', 'crypto_to_transactions'),
            ('To Related Addresses', 'crypto_to_related_addresses'),
            ('To Balance', 'crypto_to_balance')
        ])
        self.tabs.addTab(crypto_tab, "Crypto")
        
        # URL Transforms
        url_tab = self._create_transform_tab([
            ('Full Investigation', 'url_investigate'),
            ('To Redirects', 'url_to_redirects'),
            ('🌍 To Domain', 'url_to_domain'),
            ('To IP', 'url_to_ip'),
            ('To Threat Names', 'url_to_threat_names'),
            ('⚙️ To Technologies', 'url_to_technologies'),
            ('To Certificates', 'url_to_certificates')
        ])
        self.tabs.addTab(url_tab, "URL")
        
        # Company Transforms
        company_tab = self._create_transform_tab([
            ('Full Investigation', 'company_investigate'),
            ('🌍 To Domain', 'company_to_domain'),
            ('To Domains', 'company_to_domains'),
            ('To Employees', 'company_to_employees'),
            ('To Emails', 'company_to_emails'),
            ('To Social Media', 'company_to_social_media'),
            ('⚙️ To Technologies', 'company_to_technologies'),
            ('💼 To Jobs', 'company_to_jobs')
        ])
        self.tabs.addTab(company_tab, "Company")
        
        # CVE Transforms
        cve_tab = self._create_transform_tab([
            ('Full Investigation', 'cve_investigate'),
            ('To Exploits', 'cve_to_exploits'),
            ('📦 To Affected Products', 'cve_to_affected_products'),
            ('To Vendors', 'cve_to_vendors'),
            ('🩹 To Patches', 'cve_to_patches'),
            ('To References', 'cve_to_references')
        ])
        self.tabs.addTab(cve_tab, "CVE")
        
        # Malware Transforms
        malware_tab = self._create_transform_tab([
            ('Full Investigation', 'malware_investigate'),
            ('📦 To Samples', 'malware_to_samples'),
            ('To IOCs', 'malware_to_iocs'),
            ('To C2 Servers', 'malware_to_c2_servers'),
            ('⚙️ To Behavior', 'malware_to_behavior'),
            ('To Campaigns', 'malware_to_campaigns'),
            ('To Hashes', 'malware_to_hashes')
        ])
        self.tabs.addTab(malware_tab, "Malware")
        
        # Breach Transforms
        breach_tab = self._create_transform_tab([
            ('Full Investigation', 'breach_investigate'),
            ('To Breaches', 'breach_to_breaches'),
            ('🔑 To Passwords', 'breach_to_passwords'),
            ('💧 To Leaks', 'breach_to_leaks'),
            ('📋 To Pastes', 'breach_to_pastes'),
            ('To Emails', 'breach_to_emails'),
            ('To Usernames', 'breach_to_usernames')
        ])
        self.tabs.addTab(breach_tab, "Breach")
        
        layout.addWidget(self.tabs)
        
        # Progress section
        self.progress_label = QLabel("")
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        
        layout.addWidget(self.progress_label)
        layout.addWidget(self.progress_bar)
        
        # Auto-chain button
        auto_chain_btn = QPushButton("🤖 Auto-Chain Transforms (AI)")
        auto_chain_btn.clicked.connect(self._auto_chain)
        auto_chain_btn.setToolTip("AI suggests and executes next best transforms")
        layout.addWidget(auto_chain_btn)
    
    def _create_transform_tab(self, transforms):
        """Create tab with transform buttons"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        for label, transform_type in transforms:
            btn = QPushButton(label)
            btn.clicked.connect(lambda checked, t=transform_type: self._run_transform(t))
            btn.setToolTip(f"Run {transform_type}")
            layout.addWidget(btn)
        
        layout.addStretch()
        return widget
    
    def _run_transform(self, transform_type):
        selected = self.main_window.canvas.get_selected_node()
        if not selected:
            QMessageBox.warning(self, 'Transform', 'Select a node first!')
            return
        
        self.progress_label.setText(f"Running {transform_type}...")
        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, 0)
        
        from sentinel_intel.transforms.transform_engine import engine
        
        class Worker(QThread):
            finished = pyqtSignal(list)
            def __init__(self, node_id, transform_type):
                super().__init__()
                self.node_id, self.transform_type = node_id, transform_type
            def run(self):
                results = engine.execute(self.node_id, self.transform_type)
                self.finished.emit(results)
        
        self.worker = Worker(selected, transform_type)
        self.worker.finished.connect(self._on_complete)
        self.worker.start()
    
    def _on_complete(self, results):
        self.progress_bar.setVisible(False)
        if results:
            self.progress_label.setText(f"Found {len(results)} results")
            
            # Get the source node that was transformed
            selected = self.main_window.canvas.get_selected_node()
            
            # Reload graph to show new nodes
            self.main_window.canvas.reload_graph()
            
            # Re-select the source node (reload_graph deselects everything)
            if selected:
                # Small delay to ensure graph is reloaded
                from PyQt6.QtCore import QTimer
                QTimer.singleShot(100, lambda: self._refresh_node_selection(selected))
            
            self.main_window.statusbar.showMessage(f"Transform complete: {len(results)} results", 5000)
        else:
            self.progress_label.setText("ℹ️ No results")
            self.main_window.statusbar.showMessage("ℹ️ No results", 3000)
    
    def _refresh_node_selection(self, node_id: str):
        """Re-select node and refresh properties panel"""
        try:
            # Re-select the node in canvas
            self.main_window.canvas.select_node(node_id)
            # Force refresh properties panel
            self.main_window.properties_panel.update_properties(node_id)
        except Exception as e:
            print(f"Refresh error: {e}")
    
    def _auto_chain(self):
        """AI-powered auto-chaining of transforms"""
        selected = self.main_window.canvas.get_selected_node()
        if not selected:
            QMessageBox.warning(self, 'Auto-Chain', 'Select a node first!')
            return
        
        # Get node details
        from sentinel_intel.core.database import db
        nodes = [n for n in db.get_nodes() if n['id'] == selected]
        if not nodes:
            return
        
        node = nodes[0]
        entity_type = node['entity_type']
        
        # AI suggests next transforms
        suggested_transforms = self._suggest_transforms(entity_type)
        
        if not suggested_transforms:
            QMessageBox.information(self, 'Auto-Chain', 'No transforms suggested for this entity type')
            return
        
        # Ask user confirmation
        msg = f"🤖 AI suggests running these transforms:\n\n"
        for i, t in enumerate(suggested_transforms, 1):
            msg += f"{i}. {t}\n"
        msg += "\nProceed?"
        
        reply = QMessageBox.question(self, 'Auto-Chain', msg,
                                    QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        
        if reply == QMessageBox.StandardButton.Yes:
            self._run_chain(selected, suggested_transforms)
    
    def _suggest_transforms(self, entity_type: str) -> list:
        """AI suggests best transforms for entity type"""
        suggestions = {
            'email': ['email_to_breaches', 'email_to_profiles', 'email_to_domains'],
            'phone': ['phone_to_carrier', 'phone_to_location', 'phone_to_messaging_apps'],
            'ip': ['ip_to_geolocation', 'ip_to_ports', 'ip_to_vulns'],
            'domain': ['domain_to_ips', 'domain_to_subdomains', 'domain_to_tech_stack'],
            'person': ['person_to_emails', 'person_to_phones', 'person_to_profiles'],
            'username': ['username_to_platforms', 'username_to_profile_links'],
            'hash': ['hash_to_malware_families', 'hash_to_threat_names'],
            'cryptocurrency': ['crypto_to_transactions', 'crypto_to_related_addresses'],
            'url': ['url_to_domain', 'url_to_ip', 'url_to_threat_names'],
            'company': ['company_to_domains', 'company_to_employees', 'company_to_emails'],
            'cve': ['cve_to_exploits', 'cve_to_affected_products', 'cve_to_vendors'],
            'malware': ['malware_to_iocs', 'malware_to_c2_servers', 'malware_to_hashes'],
            'breach': ['breach_to_breaches', 'breach_to_passwords', 'breach_to_emails']
        }
        return suggestions.get(entity_type, [])
    
    def _run_chain(self, node_id: str, transforms: list):
        """Run chain of transforms sequentially"""
        self.progress_label.setText(f"🤖 Auto-chaining {len(transforms)} transforms...")
        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, len(transforms))
        self.progress_bar.setValue(0)
        
        from sentinel_intel.transforms.transform_engine import engine
        
        class ChainWorker(QThread):
            progress = pyqtSignal(int, str)
            finished = pyqtSignal(int)
            
            def __init__(self, node_id, transforms):
                super().__init__()
                self.node_id = node_id
                self.transforms = transforms
            
            def run(self):
                total_results = 0
                for i, transform in enumerate(self.transforms):
                    self.progress.emit(i + 1, transform)
                    results = engine.execute(self.node_id, transform)
                    total_results += len(results)
                self.finished.emit(total_results)
        
        self.chain_worker = ChainWorker(node_id, transforms)
        self.chain_worker.progress.connect(self._on_chain_progress)
        self.chain_worker.finished.connect(self._on_chain_complete)
        self.chain_worker.start()
    
    def _on_chain_progress(self, step: int, transform: str):
        self.progress_bar.setValue(step)
        self.progress_label.setText(f"Running {transform}... ({step}/{self.progress_bar.maximum()})")
    
    def _on_chain_complete(self, total_results: int):
        self.progress_bar.setVisible(False)
        self.progress_label.setText(f"Auto-chain complete: {total_results} total results")
        self.main_window.canvas.reload_graph()
        self.main_window.statusbar.showMessage(f"Auto-chain complete: {total_results} results", 5000)
        QMessageBox.information(self, 'Auto-Chain', f"🎉 Chain complete!\n\nTotal results: {total_results}")
    
    def _filter_transforms(self, text):
        """Filter transforms by search text"""
        # TODO: Implement search filtering
        pass
