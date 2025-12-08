package racetester;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.extension.ExtensionUnloadingHandler;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import javax.swing.*;
import java.awt.*;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.ArrayList;
import java.util.List;

/**
 * Main Entry Point for "Race State Auditor".
 * <p>
 * Handles lifecycle management, menu integration, and resource cleanup.
 */
public class RaceTesterExtension implements BurpExtension, ExtensionUnloadingHandler {

    // Official Name for BApp Store
    private static final String EXTENSION_NAME = "Race State Auditor";
    private RaceLogicUI mainTab;
    private MontoyaApi api;

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        api.logging().logToOutput("=== INITIALIZING: " + EXTENSION_NAME + " ===");

        try {
            api.extension().setName(EXTENSION_NAME);
            
            // Register unloading handler (CRITICAL FOR BAPP STORE)
            api.extension().registerUnloadingHandler(this);

            mainTab = new RaceLogicUI(api);
            
            // Register Suite Tab
            api.userInterface().registerSuiteTab("Race Auditor", mainTab);
            api.logging().logToOutput("INFO: UI initialized.");

            api.userInterface().registerContextMenuItemsProvider(new RaceContextMenuProvider());

            api.logging().logToOutput("=== " + EXTENSION_NAME + " READY ===");

        } catch (Throwable t) {
            logFatalError("Failed to initialize extension", t);
        }
    }

    /**
     * BApp Store Compliance: "It unloads cleanly".
     * Called when the extension is unloaded.
     */
    @Override
    public void extensionUnloaded() {
        if (mainTab != null) {
            mainTab.shutdown();
        }
        api.logging().logToOutput("INFO: " + EXTENSION_NAME + " unloaded.");
    }

    private void logFatalError(String message, Throwable t) {
        StringWriter sw = new StringWriter();
        t.printStackTrace(new PrintWriter(sw));
        api.logging().logToError("FATAL ERROR: " + message + "\n" + sw.toString());
    }

    private class RaceContextMenuProvider implements ContextMenuItemsProvider {
        @Override
        public List<Component> provideMenuItems(ContextMenuEvent event) {
            // Context Menu Text
            JMenuItem sendItem = new JMenuItem("Send to Race State Auditor");
            
            sendItem.addActionListener(l -> {
                try {
                    HttpRequestResponse requestToImport = null;

                    if (event.messageEditorRequestResponse().isPresent()) {
                        requestToImport = event.messageEditorRequestResponse().get().requestResponse();
                    } 
                    else if (event.selectedRequestResponses() != null && !event.selectedRequestResponses().isEmpty()) {
                        requestToImport = event.selectedRequestResponses().get(0);
                    }

                    if (requestToImport != null) {
                        // Bring window to front if possible (UX)
                        mainTab.importRequest(requestToImport);
                    } else {
                        api.logging().logToError("WARNING: No request selected.");
                    }

                } catch (Throwable t) {
                    logFatalError("Context Menu Error", t);
                }
            });

            List<Component> menuList = new ArrayList<>();
            menuList.add(sendItem);
            return menuList;
        }
    }
}