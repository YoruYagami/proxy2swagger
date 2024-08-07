from burp import IBurpExtender, ITab, IProxyListener, IInterceptedProxyMessage, IHttpRequestResponse
from javax.swing import JPanel, JButton, JTextArea, JScrollPane, JTextField, JFileChooser, JOptionPane, JLabel, JTabbedPane
from java.awt import BorderLayout, FlowLayout
import json

class BurpExtender(IBurpExtender, ITab, IProxyListener):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._callbacks.setExtensionName("Swagger Integration")

        # Initialize the Swagger data structure
        self.initialize_swagger_data()

        # Create tabs
        self._tabbedPane = JTabbedPane()

        # Swagger Tab
        self._swaggerPanel = self.create_swagger_panel()
        self._tabbedPane.addTab("Swagger", self._swaggerPanel)

        # Register UI components
        self._callbacks.addSuiteTab(self)
        self._callbacks.registerProxyListener(self)

    def getTabCaption(self):
        return "Swagger"

    def getUiComponent(self):
        return self._tabbedPane

    def initialize_swagger_data(self):
        """Initialize Swagger data with default values, including host from in-scope URLs."""
        host = self.get_in_scope_host()
        self.swagger_data = {
            "openapi": "3.0.0",
            "info": {
                "title": "Generated API",
                "description": "API description",
                "version": "1.0.0"
            },
            "servers": [
                {
                    "url": "http://{}".format(host),
                    "description": "HTTP server"
                },
                {
                    "url": "https://{}".format(host),
                    "description": "HTTPS server"
                }
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
            "security": [
                {
                    "Bearer": []
                }
            ]
        }

    def get_in_scope_host(self):
        """Retrieve the host from in-scope URLs."""
        history = self._callbacks.getProxyHistory()
        in_scope_urls = [self._helpers.analyzeRequest(message).getUrl() for message in history if self._callbacks.isInScope(self._helpers.analyzeRequest(message).getUrl())]
        if in_scope_urls:
            return in_scope_urls[0].getHost()
        else:
            return "localhost"  # Fallback if no in-scope URLs found

    def create_swagger_panel(self):
        """Create the UI panel for Swagger management."""
        panel = JPanel(BorderLayout())
        self._textArea = JTextArea()
        self._scrollPane = JScrollPane(self._textArea)
        buttonPanel = JPanel(FlowLayout())

        # Host field
        self._hostField = JTextField(self.get_in_scope_host(), 20)
        buttonUpdateHost = JButton("Update Host", actionPerformed=self.update_host)
        buttonSave = JButton("Save Swagger", actionPerformed=self.save_swagger_file)
        buttonLoadInScope = JButton("Load History from In-Scope", actionPerformed=self.load_in_scope)

        buttonPanel.add(JLabel("Host:"))
        buttonPanel.add(self._hostField)
        buttonPanel.add(buttonUpdateHost)
        buttonPanel.add(buttonLoadInScope)
        buttonPanel.add(buttonSave)
        panel.add(self._scrollPane, BorderLayout.CENTER)
        panel.add(buttonPanel, BorderLayout.SOUTH)

        self.update_text_area()
        return panel

    def update_text_area(self):
        """Update the text area with the current Swagger JSON data."""
        formatted_data = json.dumps(self.swagger_data, indent=4)
        self._textArea.setText(formatted_data)

    def update_host(self, event):
        """Update the host in the Swagger data based on the user's input."""
        new_host = self._hostField.getText().strip()
        if new_host:
            self.swagger_data["servers"] = [
                {
                    "url": "http://{}".format(new_host),
                    "description": "HTTP server"
                },
                {
                    "url": "https://{}".format(new_host),
                    "description": "HTTPS server"
                }
            ]
            self.update_text_area()

    def save_swagger_file(self, event):
        """Save the current Swagger JSON to a file."""
        chooser = JFileChooser()
        ret = chooser.showSaveDialog(self._textArea)
        if ret == JFileChooser.APPROVE_OPTION:
            file = chooser.getSelectedFile()
            filepath = file.getAbsolutePath()
            try:
                swagger_data = json.loads(self._textArea.getText())
                with open(filepath, 'w') as f:
                    f.write(json.dumps(swagger_data, indent=4))
                JOptionPane.showMessageDialog(self._textArea, "Swagger file saved successfully.")
            except Exception as e:
                JOptionPane.showMessageDialog(self._textArea, "Error saving file: {}".format(e))

    def load_in_scope(self, event=None):
        """Load and update Swagger data based on in-scope proxy history."""
        try:
            # Clear existing paths
            self.swagger_data["paths"].clear()
            # Retrieve the proxy history
            history = self._callbacks.getProxyHistory()
            for message in history:
                # Check if the message is in scope
                analyzed_message = self._helpers.analyzeRequest(message)
                url = analyzed_message.getUrl()
                if self._callbacks.isInScope(url):
                    self.update_swagger(message)
            self.update_text_area()
        except Exception as e:
            JOptionPane.showMessageDialog(self._textArea, "Error loading in-scope data: {}".format(e))

    def update_swagger(self, messageInfo):
        """Update the Swagger paths based on the intercepted proxy messages."""
        try:
            if isinstance(messageInfo, IHttpRequestResponse):
                requestInfo = self._helpers.analyzeRequest(messageInfo)
                responseInfo = self._helpers.analyzeResponse(messageInfo.getResponse())
                url = requestInfo.getUrl()
                method = requestInfo.getMethod().lower()
                path = url.getPath()

                # Build a basic Swagger path entry
                if path not in self.swagger_data["paths"]:
                    self.swagger_data["paths"][path] = {}

                # Initialize method data
                if method not in self.swagger_data["paths"][path]:
                    self.swagger_data["paths"][path][method] = {
                        "parameters": [],
                        "responses": {}
                    }

                # Handle query parameters
                for param in requestInfo.getParameters():
                    if param.getType() == 0:  # 0 for QUERY parameters
                        self.swagger_data["paths"][path][method]["parameters"].append({
                            "name": param.getName(),
                            "in": "query",
                            "required": True,  # Assuming query params are required
                            "schema": {
                                "type": "string"
                            }
                        })

                # Infer response description based on status code
                status_code = str(responseInfo.getStatusCode())
                description = self.get_response_description(status_code)
                self.swagger_data["paths"][path][method]["responses"][status_code] = {
                    "description": description,
                    "content": {
                        "application/json": {
                            "schema": {
                                "type": "object"
                            }
                        }
                    }
                }
        except Exception as e:
            JOptionPane.showMessageDialog(self._textArea, "Error updating Swagger: {}".format(e))

    def get_response_description(self, status_code):
        """Provide descriptions for common HTTP status codes."""
        if status_code.startswith('2'):
            return "Successful response"
        elif status_code.startswith('4'):
            return "Client error"
        elif status_code.startswith('5'):
            return "Server error"
        return "Response"

    def processProxyMessage(self, messageIsRequest, message):
        """Intercept and process proxy messages to update Swagger data."""
        if not messageIsRequest:
            self.update_swagger(message)
