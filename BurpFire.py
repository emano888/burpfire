# -*- coding: utf-8 -*-
from burp import IBurpExtender, ITab
from java.awt import BorderLayout
from java.awt.datatransfer import DataFlavor
from javax.swing import JPanel, JTextArea, JButton, JScrollPane, JPopupMenu, JMenuItem
from threading import Thread, Lock
from java.net import URL

class BurpExtender(IBurpExtender, ITab):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("BurpFire")

        # Create the UI components
        self.panel = JPanel(BorderLayout())
        self.text_area = JTextArea()
        self.send_button = JButton("Send Requests", actionPerformed=self.on_send_requests)

        # Create the right-click menu
        popup_menu = JPopupMenu()
        paste_item = JMenuItem("Paste URLs", actionPerformed=self.paste_urls)
        popup_menu.add(paste_item)
        self.text_area.setComponentPopupMenu(popup_menu)

        # Add components to panel
        self.panel.add(JScrollPane(self.text_area), BorderLayout.CENTER)
        self.panel.add(self.send_button, BorderLayout.SOUTH)

        # Register the tab
        callbacks.addSuiteTab(self)

    def getTabCaption(self):
        return "BurpFire"

    def getUiComponent(self):
        return self.panel

    def on_send_requests(self, event):
        thread = Thread(target=self.send_requests)
        thread.start()

    def send_requests(self):
        urls = self.text_area.getText().split('\n')
        threads = []
        results_lock = Lock()

        def fetch_url(url):
            url = url.strip()
            if not url:
                return
            try:
                print("Processing URL: {}".format(url))

                # Parse URL
                parsed_url = URL(url)
                host = parsed_url.getHost()
                port = parsed_url.getPort()
                protocol = parsed_url.getProtocol()

                # Determine port
                if port == -1:
                    port = 443 if protocol == "https" else 80

                # Build HTTP request
                path = parsed_url.getFile()
                request = self._helpers.buildHttpRequest(parsed_url)
                
                # Optional: Modify request headers (e.g., add custom User-Agent)
                analyzed = self._helpers.analyzeRequest(request)
                headers = list(analyzed.getHeaders())
                body = request[analyzed.getBodyOffset():]
                headers = [h for h in headers if not h.lower().startswith("user-agent:")]
                headers.append("User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0")
                request = self._helpers.buildHttpMessage(headers, body)

                # Send request using Burp's stack
                http_service = self._helpers.buildHttpService(host, port, protocol)
                response = self._callbacks.makeHttpRequest(http_service, request)
                response_info = self._helpers.analyzeResponse(response.getResponse())
                status_code = response_info.getStatusCode()

                with results_lock:
                    print("Response status: {} for URL: {}".format(status_code, url))

            except Exception as e:
                with results_lock:
                    print("Error making request to {}: {}".format(url, e))

        for url in urls:
            thread = Thread(target=fetch_url, args=(url,))
            threads.append(thread)
            thread.start()

        for thread in threads:
            thread.join()

    def paste_urls(self, event):
        clipboard = self.panel.getToolkit().getSystemClipboard()
        try:
            data = clipboard.getData(DataFlavor.stringFlavor)
            if data:
                self.text_area.append(data + '\n')
        except Exception as e:
            print("Error pasting data: {}".format(e))
