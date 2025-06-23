# -*- coding: utf-8 -*-
from burp import IBurpExtender, ITab, IExtensionStateListener
from java.awt import BorderLayout
from java.awt.datatransfer import DataFlavor
from javax.swing import JPanel, JTextArea, JButton, JScrollPane, JPopupMenu, JMenuItem
from java.net import URL, MalformedURLException
from java.util.concurrent import Executors, TimeUnit
from java.lang import Runnable
from threading import Lock

class BurpExtender(IBurpExtender, ITab, IExtensionStateListener):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._callbacks.setExtensionName("BurpFire")

        # Thread pool
        self.executor = Executors.newFixedThreadPool(10)
        self.lock = Lock()

        # Register listener
        self._callbacks.registerExtensionStateListener(self)

        # UI
        self.panel = JPanel(BorderLayout())
        self.text_area = JTextArea()
        self.send_button = JButton("Send Requests", actionPerformed=self.on_send_requests)

        popup_menu = JPopupMenu()
        paste_item = JMenuItem("Paste URLs", actionPerformed=self.paste_urls)
        popup_menu.add(paste_item)
        self.text_area.setComponentPopupMenu(popup_menu)

        self.panel.add(JScrollPane(self.text_area), BorderLayout.CENTER)
        self.panel.add(self.send_button, BorderLayout.SOUTH)

        self._callbacks.addSuiteTab(self)

    def getTabCaption(self):
        return u"BurpFire"

    def getUiComponent(self):
        return self.panel

    def on_send_requests(self, event):
        raw_text = self.text_area.getText()
        if not raw_text.strip():
            self._callbacks.printOutput(u"No URL provided.")
            return

        urls = raw_text.strip().split('\n')
        self._callbacks.printOutput(u"Total URLs detected: {}".format(len(urls)))

        for url in urls:
            url = url.strip()
            if not url.startswith("http"):
                self._callbacks.printError(u"Ignoring invalid URL: " + unicode(url))
                continue
            self.executor.submit(RequestRunnable(self, url))

    def fetch_url(self, url):
        try:
            with self.lock:
                self._callbacks.printOutput(u"==> Starting request for: {}".format(unicode(url)))

            try:
                parsed_url = URL(url)
            except MalformedURLException as e:
                with self.lock:
                    self._callbacks.printError(u"Malformed URL: {} -> {}".format(unicode(url), unicode(e)))
                return

            host = parsed_url.getHost()
            port = parsed_url.getPort()
            protocol = parsed_url.getProtocol()
            path = parsed_url.getFile()

            if port == -1:
                port = 443 if protocol == "https" else 80

            with self.lock:
                self._callbacks.printOutput(u">> Host: {}, Port: {}, Protocol: {}, Path: {}".format(
                    unicode(host), port, unicode(protocol), unicode(path)))

            request = self._helpers.buildHttpRequest(parsed_url)
            analyzed = self._helpers.analyzeRequest(request)
            headers = list(analyzed.getHeaders())
            body = request[analyzed.getBodyOffset():]

            headers = [h for h in headers if not h.lower().startswith("user-agent:")]
            headers.append(u"User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0")
            request = self._helpers.buildHttpMessage(headers, body)

            http_service = self._helpers.buildHttpService(host, port, protocol)

            with self.lock:
                self._callbacks.printOutput(u">> Sending request to: {}:{}{}".format(
                    unicode(host), port, unicode(path)))

            response = self._callbacks.makeHttpRequest(http_service, request)

            if response is None:
                with self.lock:
                    self._callbacks.printError(u"!!! makeHttpRequest returned None for: {}".format(unicode(url)))
                return

            raw_response = response.getResponse()
            if raw_response is None:
                with self.lock:
                    self._callbacks.printError(u"!!! getResponse() returned None for: {}".format(unicode(url)))
                return

            response_info = self._helpers.analyzeResponse(raw_response)
            status_code = response_info.getStatusCode()

            with self.lock:
                self._callbacks.printOutput(u"[{}] {}".format(status_code, unicode(url)))

        except Exception as e:
            with self.lock:
                try:
                    self._callbacks.printError(u"!!! Error processing '{}': {}".format(unicode(url), unicode(e)))
                except:
                    self._callbacks.printError(u"!!! Error processing URL (encoding failure)")

    def paste_urls(self, event):
        clipboard = self.panel.getToolkit().getSystemClipboard()
        try:
            data = clipboard.getData(DataFlavor.stringFlavor)
            if data:
                self.text_area.append(data + '\n')
                self._callbacks.printOutput(u"URLs pasted into text field.")
        except Exception as e:
            self._callbacks.printError(u"Error pasting from clipboard: {}".format(unicode(e)))
            
        try:
            if not self.executor.awaitTermination(5, TimeUnit.SECONDS):
                self._callbacks.printError(u"Some tasks may not have completed correctly.")
        except Exception as e:
            self._callbacks.printError(u"Error terminating executor: {}".format(unicode(e)))

class RequestRunnable(Runnable):
    def __init__(self, parent, url):
        self.parent = parent
        self.url = url

    def run(self):
        self.parent.fetch_url(self.url)
