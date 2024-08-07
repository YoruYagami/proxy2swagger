# 🌐 proxy2swagger

<p align="center">
  <a href="#"><img alt="starsBDG" src="https://img.shields.io/github/stars/YoruYagami/proxy2swagger?style=for-the-badge"></a>
  <a href="#"><img alt="licenseBDG" src="https://img.shields.io/github/license/YoruYagami/proxy2swagger?style=for-the-badge"></a>
  <a href="#"><img alt="languageBDG" src="https://img.shields.io/badge/LANGUAGE-Python3-blue?style=for-the-badge"></a>
</p>

proxy2swagger is a Burp Suite extension that generates Swagger (OpenAPI) specifications from proxy history, simplifying API documentation and testing.

## ✨ Features

- 🛠 **Automatic Swagger Generation:** Create Swagger (OpenAPI 3.0) documentation from in-scope proxy history.
- 🖥 **UI for Swagger Management:** Manage, edit and view the generated Swagger data via a user interface.
- 🌐 **Host Management:** Update the host in the Swagger specification in case you change scope.
- 💾 **Save and Load Swagger Files:** Save the Swagger documentation to a file and load in-scope proxy history to update Swagger data.

## 🚀 Installation

1. **Download or Clone the Repository:**
   ```bash
   git clone https://github.com/YoruYagami/proxy2swagger.git
   ```
2. **Download Jython Standalone:**
   - Download the Jython standalone JAR from [Jython's official website](https://www.jython.org/downloads.html).
3. **Compile the Extension:** Use Jython, Java, or your preferred method.
4. **Load the Extension in Burp Suite:**
   - Open Burp Suite.
   - Go to the "Extender" tab.
   - Click on the "Extensions" tab.
   - Click "Add" and select the Jython standalone JAR as the extension type.
   - Load the python extension file.

## 🤝 Contributing

Contributions are welcome! Please open an issue or submit a pull request.

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
