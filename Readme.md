# SafeShare Chrome Extension

## Overview
SafeShare is a Chrome extension designed to enhance security in collaborative environments and ensure compliance with data privacy regulations. This repository contains the code for the SafeShare Chrome extension, and this guide provides detailed steps on how to import it into your web extension.

## Prerequisites
Before proceeding, ensure you have the following:
- A working Chrome browser
- A GitHub account
- Basic knowledge of managing Chrome extensions

## Steps to Import SafeShare Chrome Extension

### 1. Clone the Repository
Start by cloning the SafeShare repository to your local machine. Open a terminal or command prompt and run the following command:

git clone https://github.com/iamramishka/SafeShare.git


2. Open Chrome Browser
Open your Chrome browser.

3. Access the Extensions Page
In the Chrome address bar, type the following and press Enter:

chrome://extensions
4. Enable Developer Mode
On the chrome://extensions page, toggle the Developer mode switch located at the top-right corner.

5. Load the Unpacked Extension
Click the Load unpacked button.

In the file dialog, navigate to the folder where you cloned the SafeShare repository.
Select the folder containing the project files.

6. Test the Extension
Once the extension is loaded, it should appear in the list of installed extensions. You can now test the extension by interacting with it in your browser.

To confirm it's working:
Click on the extension icon in the browser toolbar to launch it.
Test its functionality according to the extension’s intended features.

7. Debugging the Extension
If you encounter issues or want to debug the extension:
Right-click on the extension's icon in the browser toolbar.
Select Inspect popup to open the developer tools for the extension popup.
You can also inspect the background page by clicking on Inspect background page in the Extensions page.

8. Update the Extension
To keep the extension updated:
Pull the latest changes from the repository using:

git pull

Then, reload the extension in chrome://extensions by clicking the Reload button.

10. Packaging the Extension (Optional)
If you want to distribute your extension or upload it to the Chrome Web Store, you can package the extension:
Go to chrome://extensions and click Pack extension.
Select the directory of your extension and choose whether you want to include the private key.
Click Pack extension to generate a .crx file for distribution.

Contributing
We welcome contributions to the SafeShare project! If you'd like to contribute:
Fork the repository and create a new branch for your feature or fix.
Make the necessary changes and thoroughly test them.
Submit a pull request with a detailed description of your changes.
Please ensure your code adheres to the existing coding standards and passes any tests before submitting.

License
This project is licensed under the MIT License - see the LICENSE file for details.

Contact
For any questions, feedback, or support, please reach out to:

Email: iamramishka@gmail.com
GitHub: iamramishka
