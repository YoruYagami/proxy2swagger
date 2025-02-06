# -*- coding: utf-8 -*-
from burp import IBurpExtender, ITab, IProxyListener, IScannerListener, IHttpRequestResponse
from javax.swing import JPanel, JButton, JTextArea, JScrollPane, JTextField, JFileChooser, JOptionPane, JLabel, JTabbedPane, JSplitPane, SwingUtilities
from java.awt import BorderLayout, FlowLayout, Dimension
import json, os

class BurpExtender(IBurpExtender, ITab, IProxyListener, IScannerListener):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._callbacks.setExtensionName("Dynamic OpenAPI Generator")

        # Initialize the OpenAPI (Swagger) data structure.
        self.initialize_swagger_data()

        # Build the UI.
        self._tabbedPane = JTabbedPane()
        self._mainPanel = self.create_main_panel()
        self._tabbedPane.addTab("OpenAPI", self._mainPanel)

        # Register UI and listeners.
        self._callbacks.addSuiteTab(self)
        self._callbacks.registerProxyListener(self)
        self._callbacks.registerScannerListener(self)

    # ITab interface.
    def getTabCaption(self):
        return "OpenAPI"

    def getUiComponent(self):
        return self._tabbedPane

    def initialize_swagger_data(self):
        host = self.get_in_scope_host()
        self.swagger_data = {
            "openapi": "3.0.0",
            "info": {
                "title": "Generated API",
                "description": "API description",
                "version": "1.0.0"
            },
            "servers": [
                {"url": "http://{}".format(host), "description": "HTTP server"},
                {"url": "https://{}".format(host), "description": "HTTPS server"}
            ],
            "paths": {},
            "components": {
                "securitySchemes": {
                    "Bearer": {
                        "type": "http",
                        "scheme": "bearer",
                        "bearerFormat": "JWT"
                    }
                }
            },
            "security": [{"Bearer": []}]
        }

    def get_in_scope_host(self):
        history = self._callbacks.getProxyHistory()
        for message in history:
            reqInfo = self._helpers.analyzeRequest(message)
            url = reqInfo.getUrl()
            if self._callbacks.isInScope(url):
                return url.getHost()
        return "localhost"

    def create_main_panel(self):
        mainPanel = JPanel(BorderLayout())

        # Toolbar panel at the top.
        toolbar = JPanel(FlowLayout(FlowLayout.LEFT))
        self._hostField = JTextField(self.get_in_scope_host(), 15)
        btnUpdateHost = JButton("Update Host", actionPerformed=self.update_host)
        btnLoadInScope = JButton("Load In-Scope", actionPerformed=self.load_in_scope)
        btnSave = JButton("Save OpenAPI", actionPerformed=self.save_swagger_file)
        btnAutoExport = JButton("Auto-Export", actionPerformed=self.auto_export)
        btnApplyChanges = JButton("Apply Changes", actionPerformed=self.apply_changes)

        toolbar.add(JLabel("Host:"))
        toolbar.add(self._hostField)
        toolbar.add(btnUpdateHost)
        toolbar.add(btnLoadInScope)
        toolbar.add(btnSave)
        toolbar.add(btnAutoExport)
        toolbar.add(btnApplyChanges)
        mainPanel.add(toolbar, BorderLayout.NORTH)

        # Center pane: JSON preview/editor area.
        self._textArea = JTextArea()
        self._textArea.setEditable(True)
        jsonScroll = JScrollPane(self._textArea)
        mainPanel.add(jsonScroll, BorderLayout.CENTER)

        # Status bar at the bottom.
        self._statusLabel = JLabel("Ready")
        mainPanel.add(self._statusLabel, BorderLayout.SOUTH)

        # Initialize display.
        self.update_text_area()
        return mainPanel

    def update_text_area(self):
        formatted_data = json.dumps(self.swagger_data, indent=4)
        self._textArea.setText(formatted_data)
        self._textArea.setCaretPosition(0)

    def update_host(self, event):
        new_host = self._hostField.getText().strip()
        if new_host:
            self.swagger_data["servers"] = [
                {"url": "http://{}".format(new_host), "description": "HTTP server"},
                {"url": "https://{}".format(new_host), "description": "HTTPS server"}
            ]
            self.update_text_area()
            self._statusLabel.setText("Updated host to: {}".format(new_host))

    def save_swagger_file(self, event):
        chooser = JFileChooser()
        ret = chooser.showSaveDialog(self._textArea)
        if ret == JFileChooser.APPROVE_OPTION:
            file = chooser.getSelectedFile()
            filepath = file.getAbsolutePath()
            # Append .json if not already present.
            if not filepath.lower().endswith(".json"):
                filepath += ".json"
            try:
                swagger_data = json.loads(self._textArea.getText())
                with open(filepath, 'w') as f:
                    f.write(json.dumps(swagger_data, indent=4))
                JOptionPane.showMessageDialog(self._textArea, "OpenAPI file saved successfully.")
                self._statusLabel.setText("Saved OpenAPI spec to: {}".format(filepath))
            except Exception as e:
                JOptionPane.showMessageDialog(self._textArea, "Error saving file: {}".format(e))
                self._statusLabel.setText("Error saving file.")

    def auto_export(self, event):
        default_path = os.path.join(os.path.expanduser("~"), "generated_openapi.json")
        try:
            with open(default_path, 'w') as f:
                f.write(json.dumps(self.swagger_data, indent=4))
            JOptionPane.showMessageDialog(self._textArea, "Auto-exported OpenAPI spec to:\n{}".format(default_path))
            self._statusLabel.setText("Auto-exported spec to: {}".format(default_path))
        except Exception as e:
            JOptionPane.showMessageDialog(self._textArea, "Auto-export error: {}".format(e))
            self._statusLabel.setText("Auto-export error.")

    def apply_changes(self, event):
        """
        Allow the user to edit the JSON in the text area and then apply those changes to update
        the internal swagger_data. If the JSON is invalid, display an error message.
        """
        try:
            new_data = json.loads(self._textArea.getText())
            self.swagger_data = new_data
            self._statusLabel.setText("Applied changes from JSON editor.")
        except Exception as e:
            JOptionPane.showMessageDialog(self._textArea, "Invalid JSON: {}".format(e))
            self._statusLabel.setText("Error applying changes.")

    def load_in_scope(self, event=None):
        try:
            self.swagger_data["paths"].clear()
            history = self._callbacks.getProxyHistory()
            for message in history:
                analyzed_message = self._helpers.analyzeRequest(message)
                url = analyzed_message.getUrl()
                if self._callbacks.isInScope(url):
                    self.update_swagger(message)
            self.update_text_area()
            self._statusLabel.setText("Loaded in-scope history; updated endpoints.")
        except Exception as e:
            JOptionPane.showMessageDialog(self._textArea, "Error loading in-scope data: {}".format(e))
            self._statusLabel.setText("Error loading in-scope data.")

    def update_swagger(self, messageInfo):
        try:
            if isinstance(messageInfo, IHttpRequestResponse):
                reqInfo = self._helpers.analyzeRequest(messageInfo)
                response_bytes = messageInfo.getResponse()
                if response_bytes is None:
                    return
                respInfo = self._helpers.analyzeResponse(response_bytes)
                url = reqInfo.getUrl()
                method = reqInfo.getMethod().lower()
                path = url.getPath()

                if path not in self.swagger_data["paths"]:
                    self.swagger_data["paths"][path] = {}
                if method not in self.swagger_data["paths"][path]:
                    self.swagger_data["paths"][path][method] = {"parameters": [], "responses": {}}

                for param in reqInfo.getParameters():
                    if param.getType() == 0:  # Query parameter.
                        if not any(p["name"] == param.getName() for p in self.swagger_data["paths"][path][method]["parameters"]):
                            self.swagger_data["paths"][path][method]["parameters"].append({
                                "name": param.getName(),
                                "in": "query",
                                "required": True,
                                "schema": {"type": "string"}
                            })

                status_code = str(respInfo.getStatusCode())
                description = self.get_response_description(status_code)
                self.swagger_data["paths"][path][method]["responses"][status_code] = {
                    "description": description,
                    "content": {
                        "application/json": {
                            "schema": {"type": "object"}
                        }
                    }
                }
                SwingUtilities.invokeLater(self.update_text_area)
        except Exception as e:
            JOptionPane.showMessageDialog(self._textArea, "Error updating OpenAPI spec: {}".format(e))

    def get_response_description(self, status_code):
        if status_code.startswith('2'):
            return "Successful response"
        elif status_code.startswith('4'):
            return "Client error"
        elif status_code.startswith('5'):
            return "Server error"
        return "Response"

    # IProxyListener interface.
    def processProxyMessage(self, messageIsRequest, message):
        if not messageIsRequest:
            self.update_swagger(message)
            SwingUtilities.invokeLater(self.update_text_area)

    # IScannerListener interface.
    def newScanIssue(self, issue):
        try:
            httpMessages = issue.getHttpMessages()
            if httpMessages:
                for message in httpMessages:
                    self.update_swagger(message)
                SwingUtilities.invokeLater(self.update_text_area)
                self._statusLabel.setText("Processed new scan issue.")
        except Exception as e:
            JOptionPane.showMessageDialog(self._textArea, "Error processing scan issue: {}".format(e))
            self._statusLabel.setText("Error processing scan issue.")
