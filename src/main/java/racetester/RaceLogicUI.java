package racetester;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.core.ByteArray;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.JTableHeader;
import java.awt.*;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * Main UI and Logic controller for Race State Auditor.
 * Handles the configuration, threading, execution, and heuristic analysis of race conditions.
 */
public class RaceLogicUI extends JPanel {

    private final MontoyaApi api;
    
    // --- UI COMPONENTS ---
    private final HttpRequestEditor targetEditor;
    private final HttpRequestEditor probeEditor;
    private final JTabbedPane inputTabs;
    private final JLabel statusLabel;
    private final JLabel verdictLabel;
    private final JTextArea logArea;
    private final DefaultTableModel resultsModel;
    private final JTabbedPane resultsTabs;
    private final JButton startButton;
    private final JCheckBox chkEnableHttp2;
    private final JTextField txtProbeRegex;
    
    // --- DATA OBJECTS ---
    private HttpRequest currentTargetRequest;
    private HttpService currentTargetService; 
    
    private HttpRequest currentProbeRequest;
    private HttpService currentProbeService;
    
    // --- THREADING ---
    private volatile boolean isRunning = false;
    private Thread analysisThread;
    private ExecutorService requestPool;
    
    // --- ANALYSIS STATE ---
    private int baselineStatus = 0;
    private String baselineHash = "";
    private boolean isErrorBase = false;

    // --- COLORS (Modern Theme) ---
    private final Color COLOR_BG_HEADER = new Color(35, 39, 42);    
    private final Color COLOR_TEXT_HEADER = new Color(245, 245, 245);
    private final Color COLOR_ACCENT = new Color(58, 123, 213); 
    private final Color COLOR_STOP = new Color(231, 76, 60);    
    private final Color COLOR_BG_PANEL = new Color(248, 249, 250);  
    private final Color COLOR_VULNERABLE = new Color(231, 76, 60);  // Red (Critical)
    private final Color COLOR_HIGH = new Color(230, 126, 34);       // Orange (High)
    private final Color COLOR_MEDIUM = new Color(241, 196, 15);     // Yellow (Medium)
    private final Color COLOR_SAFE = new Color(46, 204, 113);       // Green (Safe)
    private final Color COLOR_NEUTRAL = new Color(149, 165, 166);   
    private final Color COLOR_INFO = new Color(52, 152, 219);       
    private final Color COLOR_FAILED = new Color(108, 117, 125);    

    // --- INNER CLASS: PROBE RESULT ---
    private static class ProbeResult {
        String value;
        int count;
        boolean isError;

        ProbeResult(String value, int count, boolean isError) {
            this.value = value;
            this.count = count;
            this.isError = isError;
        }
        
        @Override
        public String toString() {
            return value + " (Count: " + count + ")";
        }
    }

    public RaceLogicUI(MontoyaApi api) {
        this.api = api;
        this.setLayout(new BorderLayout());
        this.setBackground(COLOR_BG_PANEL);

        // ====================================================================
        // 1. HEADER & ACTIONS
        // ====================================================================
        JPanel topPanel = new JPanel(new BorderLayout());
        topPanel.setBackground(COLOR_BG_HEADER);
        topPanel.setBorder(new EmptyBorder(15, 20, 15, 20));

        JPanel titlePanel = new JPanel(new GridLayout(2, 1));
        titlePanel.setOpaque(false);
        
        JLabel title = new JLabel("RACE STATE AUDITOR");
        title.setForeground(COLOR_TEXT_HEADER);
        title.setFont(new Font("Segoe UI", Font.BOLD, 18));
        
        JLabel subtitle = new JLabel("Heuristic Concurrency & State Verification Engine");
        subtitle.setForeground(new Color(180, 180, 180));
        subtitle.setFont(new Font("Segoe UI", Font.PLAIN, 12));
        titlePanel.add(title);
        titlePanel.add(subtitle);

        JPanel actionPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 20, 0));
        actionPanel.setOpaque(false);

        verdictLabel = new JLabel("READY", SwingConstants.CENTER);
        verdictLabel.setFont(new Font("Segoe UI", Font.BOLD, 13));
        verdictLabel.setForeground(Color.WHITE);
        verdictLabel.setBackground(COLOR_NEUTRAL);
        verdictLabel.setOpaque(true);
        verdictLabel.setPreferredSize(new Dimension(200, 40));
        
        startButton = createStyledButton(" ▶ START AUDIT ");
        startButton.addActionListener(e -> {
            if (isRunning) stopAnalysis();
            else startAnalysisWorkflow();
        });

        actionPanel.add(verdictLabel);
        actionPanel.add(startButton);
        topPanel.add(titlePanel, BorderLayout.WEST);
        topPanel.add(actionPanel, BorderLayout.EAST);

        // ====================================================================
        // 2. MAIN SPLIT PANE
        // ====================================================================
        JSplitPane splitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
        splitPane.setResizeWeight(0.45); 
        splitPane.setBorder(null);
        splitPane.setDividerSize(3);
        splitPane.setBackground(COLOR_BG_PANEL);

        // --- LEFT: INPUT TABS ---
        inputTabs = new JTabbedPane();
        inputTabs.setFont(new Font("Segoe UI", Font.PLAIN, 12));
        
        targetEditor = api.userInterface().createHttpRequestEditor();
        inputTabs.addTab("Target Request (Attack)", targetEditor.uiComponent());

        probeEditor = api.userInterface().createHttpRequestEditor();
        JPanel probeContainer = new JPanel(new BorderLayout());
        probeContainer.add(probeEditor.uiComponent(), BorderLayout.CENTER);
        
        JPanel probeSettings = new JPanel(new FlowLayout(FlowLayout.LEFT));
        probeSettings.setBackground(Color.WHITE);
        probeSettings.setBorder(new EmptyBorder(5,5,5,5));
        probeSettings.add(new JLabel("Match String / Regex: "));
        txtProbeRegex = new JTextField(20);
        txtProbeRegex.setToolTipText("Enter text to find. We will count how many times it appears.");
        probeSettings.add(txtProbeRegex);
        
        JButton btnClearProbe = new JButton("Clear Probe");
        btnClearProbe.setMargin(new Insets(2,5,2,5));
        btnClearProbe.addActionListener(e -> clearProbe());
        probeSettings.add(btnClearProbe);
        
        probeSettings.add(new JLabel("<html><i>(Counts occurrences to detect duplicates)</i></html>"));
        probeContainer.add(probeSettings, BorderLayout.SOUTH);

        inputTabs.addTab("Probe Request (Optional)", probeContainer);

        splitPane.setLeftComponent(inputTabs);

        // --- RIGHT: RESULTS & LEGEND ---
        JPanel resultsPanel = new JPanel(new BorderLayout());
        
        resultsTabs = new JTabbedPane();
        resultsTabs.setFont(new Font("Segoe UI", Font.PLAIN, 12));
        
        String[] columnNames = {"#", "Code", "Length", "Body Hash (MD5)", "Analysis Note"};
        resultsModel = new DefaultTableModel(columnNames, 0) {
            @Override
            public boolean isCellEditable(int row, int column) { return false; }
        };
        JTable resultsTable = new JTable(resultsModel);
        setupTableStyle(resultsTable);
        
        resultsTabs.addTab("Attack Results", new JScrollPane(resultsTable));

        logArea = new JTextArea();
        logArea.setEditable(false);
        logArea.setFont(new Font("Consolas", Font.PLAIN, 12));
        logArea.setBackground(new Color(40, 44, 52)); 
        logArea.setForeground(new Color(220, 223, 228));
        logArea.setMargin(new Insets(10, 10, 10, 10)); 
        resultsTabs.addTab("Execution Logs", new JScrollPane(logArea));

        resultsPanel.add(resultsTabs, BorderLayout.CENTER);
        
        // --- UNIFIED RISK LEGEND ---
        JPanel legendPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 15, 5));
        legendPanel.setBackground(Color.WHITE);
        legendPanel.setBorder(new EmptyBorder(5, 5, 5, 5));
        legendPanel.add(new JLabel("Risk Legend:"));
        legendPanel.add(createLegendLabel("CRITICAL (Duplication)", COLOR_VULNERABLE));
        legendPanel.add(createLegendLabel("HIGH (Silent Dupes)", COLOR_HIGH));
        legendPanel.add(createLegendLabel("MEDIUM (Idempotent/State)", COLOR_MEDIUM));
        legendPanel.add(createLegendLabel("SAFE", COLOR_SAFE));
        
        resultsPanel.add(legendPanel, BorderLayout.SOUTH);

        splitPane.setRightComponent(resultsPanel);

        // ====================================================================
        // 3. SETTINGS BAR (Bottom)
        // ====================================================================
        JPanel bottomBar = new JPanel(new BorderLayout());
        bottomBar.setBorder(new EmptyBorder(5, 15, 5, 15));
        bottomBar.setBackground(new Color(230, 230, 230));
        
        JPanel settingsPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        settingsPanel.setOpaque(false);
        chkEnableHttp2 = new JCheckBox("Force HTTP/2 Multiplexing (Single-Packet Approx)");
        chkEnableHttp2.setFont(new Font("Segoe UI", Font.BOLD, 11));
        chkEnableHttp2.setOpaque(false);
        settingsPanel.add(chkEnableHttp2);

        statusLabel = new JLabel("Waiting for request...");
        statusLabel.setFont(new Font("Segoe UI", Font.PLAIN, 11));
        statusLabel.setForeground(Color.GRAY);
        
        bottomBar.add(settingsPanel, BorderLayout.WEST);
        bottomBar.add(statusLabel, BorderLayout.EAST);

        add(topPanel, BorderLayout.NORTH);
        add(splitPane, BorderLayout.CENTER);
        add(bottomBar, BorderLayout.SOUTH);
        
        log("UI Initialized. Ready.");
    }

    private JLabel createLegendLabel(String text, Color color) {
        JLabel l = new JLabel(text);
        l.setOpaque(true);
        l.setBackground(color);
        l.setForeground(color == COLOR_MEDIUM ? Color.BLACK : Color.WHITE);
        l.setFont(new Font("Segoe UI", Font.BOLD, 10));
        l.setBorder(new EmptyBorder(2, 5, 2, 5));
        return l;
    }

    // --- PUBLIC METHODS ---

    public void importRequest(HttpRequestResponse reqResp) {
        if (reqResp == null || reqResp.request() == null) return;
        
        int selectedIndex = inputTabs.getSelectedIndex();
        
        if (selectedIndex == 0) { // Target Tab
            this.currentTargetRequest = reqResp.request();
            this.currentTargetService = reqResp.httpService();
            targetEditor.setRequest(currentTargetRequest);
            log("--- TARGET LOADED ---");
            setStatus("Target Loaded: " + currentTargetRequest.url(), false);
            
            // Auto-detect protocol for HTTP/2 checkbox
            new Thread(() -> {
                try {
                    HttpRequestResponse probe = api.http().sendRequest(currentTargetRequest);
                    boolean h2 = probe.response().httpVersion().contains("HTTP/2");
                    SwingUtilities.invokeLater(() -> chkEnableHttp2.setSelected(h2));
                } catch (Exception e) {}
            }).start();
            
        } else { // Probe Tab
            this.currentProbeRequest = reqResp.request();
            this.currentProbeService = reqResp.httpService();
            probeEditor.setRequest(currentProbeRequest);
            log("--- PROBE LOADED ---");
            setStatus("Probe Loaded: " + currentProbeRequest.url(), false);
            txtProbeRegex.requestFocus();
        }
        
        resultsModel.setRowCount(0);
        setVerdict("READY", COLOR_NEUTRAL);
    }
    
    private void clearProbe() {
        this.currentProbeRequest = null;
        this.currentProbeService = null;
        probeEditor.setRequest(HttpRequest.httpRequest().withBody("")); 
        txtProbeRegex.setText("");
        log("--- PROBE CLEARED ---");
        setStatus("Probe cleared. Attack will run without verification.", false);
    }
    
    /**
     * Cleanly shuts down active threads. Required for BApp Store compliance.
     */
    public void shutdown() {
        stopAnalysis();
        log("Extension unloading. Resources cleaned.");
    }
    
    private void stopAnalysis() {
        isRunning = false;
        if (analysisThread != null && analysisThread.isAlive()) analysisThread.interrupt();
        if (requestPool != null && !requestPool.isShutdown()) requestPool.shutdownNow();
        
        SwingUtilities.invokeLater(() -> {
            startButton.setText(" ▶ START AUDIT ");
            startButton.setBackground(COLOR_ACCENT);
            statusLabel.setText("Analysis stopped by user/system.");
        });
        log("!!! ANALYSIS STOPPED !!!");
    }

    // --- ANALYSIS LOGIC ---

    private void startAnalysisWorkflow() {
        if (isRunning) return;
        
        // Ensure Target Request is valid and has updated Content-Length
        if (targetEditor.getRequest() != null) {
            HttpRequest editorReq = targetEditor.getRequest();
            // If service (Host/Port) is missing, try to recover it
            if (editorReq.httpService() == null) {
                if (currentTargetService != null) editorReq = editorReq.withService(currentTargetService);
                else {
                    HttpService manualService = recoverServiceFromHeaders(editorReq);
                    if (manualService != null) editorReq = editorReq.withService(manualService);
                }
            }
            currentTargetRequest = fixContentLength(editorReq);
        }
        
        // Handle Optional Probe
        boolean probeExists = false;
        try {
            if (probeEditor.getRequest() != null) {
                HttpRequest editorProbe = probeEditor.getRequest();
                String url = null;
                try { url = editorProbe.url(); } catch (Exception e) {}
                
                if (url != null && !url.isEmpty()) {
                    if (editorProbe.httpService() == null) {
                        if (currentProbeService != null) editorProbe = editorProbe.withService(currentProbeService);
                        else {
                            HttpService manualService = recoverServiceFromHeaders(editorProbe);
                            if (manualService != null) editorProbe = editorProbe.withService(manualService);
                        }
                    }
                    if (editorProbe.httpService() != null) {
                        currentProbeRequest = fixContentLength(editorProbe);
                        probeExists = true;
                    }
                }
            }
        } catch (Exception e) { probeExists = false; }
        
        if (!probeExists) currentProbeRequest = null; 

        if (currentTargetRequest == null || currentTargetRequest.httpService() == null) {
            JOptionPane.showMessageDialog(this, "Target Request invalid or missing HTTP Service (Host/Port). Please Import again.");
            return;
        }

        // Setup UI for Running state
        isRunning = true;
        resultsModel.setRowCount(0);
        setVerdict("RUNNING...", COLOR_INFO);
        startButton.setText(" ■ STOP AUDIT ");
        startButton.setBackground(COLOR_STOP);
        resultsTabs.setSelectedIndex(1); 
        log("\n--- STARTING ANALYSIS ---");
        
        // Reset state
        baselineStatus = 0;
        baselineHash = "";
        isErrorBase = false;

        final boolean useProbe = probeExists;
        final boolean useHttp2 = chkEnableHttp2.isSelected();
        final String userSearchInput = txtProbeRegex.getText().trim();

        if (useProbe) {
            log("Probe Status: ACTIVE (Counting occurrences of: '" + (userSearchInput.isEmpty() ? "HASH" : userSearchInput) + "')");
        } else {
            log("Probe Status: INACTIVE (Standard Attack Only)");
        }

        // Start Analysis Thread
        analysisThread = new Thread(() -> {
            try {
                if (!isRunning) return;
                
                ProbeResult initialProbe = null;
                if (useProbe) {
                    log("[1] Executing Initial State Probe...");
                    initialProbe = executeProbe(userSearchInput);
                    log("    > Initial: " + initialProbe.toString());
                }

                if (!isRunning) return;
                log("[2] Preparing concurrent threads (" + (useHttp2 ? "HTTP/2 Mux" : "Standard") + ")...");
                List<HttpResponse> attackResults = executeRaceAttack(useHttp2);

                if (!isRunning) return;
                ProbeResult finalProbe = null;
                if (useProbe) {
                    Thread.sleep(500); // Wait for DB consistency
                    log("[3] Executing Final State Probe...");
                    finalProbe = executeProbe(userSearchInput);
                    log("    > Final: " + finalProbe.toString());
                }

                if (isRunning) {
                    analyzeResults(attackResults, initialProbe, finalProbe);
                }

            } catch (InterruptedException ie) {
                log("Process Interrupted.");
            } catch (Throwable t) {
                logError("Fatal error during analysis", t);
                setVerdict("ERROR", COLOR_VULNERABLE);
            } finally {
                SwingUtilities.invokeLater(() -> {
                    isRunning = false;
                    startButton.setText(" ▶ START AUDIT ");
                    startButton.setBackground(COLOR_ACCENT);
                });
            }
        });
        
        analysisThread.start();
    }

    // --- SERVICE AND HEADER REPAIR ---
    
    private HttpService recoverServiceFromHeaders(HttpRequest req) {
        String host = req.headerValue("Host");
        if (host != null) {
            boolean secure = true; 
            int port = 443;
            if (host.contains(":")) {
                String[] parts = host.split(":");
                host = parts[0];
                try { port = Integer.parseInt(parts[1]); } catch(Exception e){}
            }
            return HttpService.httpService(host, port, secure);
        }
        return null;
    }

    private HttpRequest fixContentLength(HttpRequest req) {
        if (req == null) return null;
        try {
            if (req.body() != null) {
                return req.withRemovedHeader("Content-Length")
                          .withHeader("Content-Length", String.valueOf(req.body().length()));
            }
        } catch (Exception e) { }
        return req;
    }

    // --- PROBE EXECUTION WITH COUNTING ---
    
    private ProbeResult executeProbe(String input) {
        try {
            if (currentProbeRequest == null || currentProbeRequest.httpService() == null) 
                return new ProbeResult("[Error: No Service]", 0, true);

            HttpResponse resp = api.http().sendRequest(currentProbeRequest).response();
            String responseBody = resp.bodyToString();
            
            log("[Probe] Body Len: " + resp.body().length());
            
            // If no input, use hash (Count 1 if body exists, 0 if empty)
            if (input.isEmpty()) {
                String hash = getShortHash(calculateMD5(resp.body()));
                return new ProbeResult(hash, resp.body().length() > 0 ? 1 : 0, false);
            } 
            
            int count = 0;
            String matchedValue = "[No Match]";

            // Strategy 1: Exact Literal Search
            if (responseBody.contains(input)) {
                count = countOccurrences(responseBody, input);
                matchedValue = input;
                log("[Probe] Literal Match Found. Count: " + count);
                return new ProbeResult(matchedValue, count, false);
            }

            // Strategy 2: Normalized Search (Ignore whitespace differences)
            String normalizedBody = responseBody.replaceAll("\\s+", "");
            String normalizedInput = input.replaceAll("\\s+", "");
            
            if (normalizedBody.contains(normalizedInput)) {
                count = countOccurrences(normalizedBody, normalizedInput);
                matchedValue = input + " (Normalized)";
                log("[Probe] Normalized Match Found. Count: " + count);
                return new ProbeResult(matchedValue, count, false);
            }

            // Strategy 3: Regex Search
            try {
                Pattern p = Pattern.compile(input, Pattern.DOTALL | Pattern.MULTILINE);
                Matcher m = p.matcher(responseBody);
                while (m.find()) {
                    count++;
                    if (count == 1) {
                        matchedValue = (m.groupCount() > 0) ? m.group(1).trim() : m.group(0).trim();
                    }
                }
                if (count > 0) {
                    log("[Probe] Regex Matches: " + count);
                    return new ProbeResult(matchedValue, count, false);
                }
            } catch (Exception e) {}

            log("[Probe] Not Found.");
            return new ProbeResult("[No Match]", 0, false);

        } catch (Exception e) {
            log("Probe Error: " + e.getMessage());
            return new ProbeResult("[Error]", 0, true);
        }
    }
    
    private int countOccurrences(String haystack, String needle) {
        if (needle.isEmpty()) return 0;
        return (haystack.length() - haystack.replace(needle, "").length()) / needle.length();
    }
    
    private String truncate(String s) {
        if (s == null) return "";
        return s.length() > 30 ? s.substring(0, 30) + "..." : s;
    }

    private List<HttpResponse> executeRaceAttack(boolean useHttp2) throws InterruptedException {
        SwingUtilities.invokeLater(() -> statusLabel.setText("Status: Sending burst..."));
        
        int threads = 20;
        List<HttpResponse> results = Collections.synchronizedList(new ArrayList<>());
        CountDownLatch readyGate = new CountDownLatch(threads);
        CountDownLatch fireGate = new CountDownLatch(1);
        CountDownLatch finishLatch = new CountDownLatch(threads);
        
        // Store pool globally to shutdown on cancel
        requestPool = useHttp2 ? Executors.newCachedThreadPool() : Executors.newFixedThreadPool(threads);

        for(int i=0; i<threads; i++) {
            requestPool.submit(() -> {
                try {
                    readyGate.countDown(); 
                    fireGate.await(); 
                    if (currentTargetRequest.httpService() != null) {
                        HttpRequestResponse rr = api.http().sendRequest(currentTargetRequest);
                        results.add(rr.response());
                    } else {
                        api.logging().logToError("Thread fail: Request has no HTTP Service");
                    }
                } catch (Exception e) {
                    if (!(e instanceof InterruptedException)) {
                        api.logging().logToError("Thread fail: " + e.getMessage());
                    }
                } finally {
                    finishLatch.countDown();
                }
            });
        }

        readyGate.await(); 
        if (!isRunning) { requestPool.shutdownNow(); return results; }
        
        log("    > Gates aligned. Syncing...");
        Thread.sleep(300); // JVM Stabilization
        fireGate.countDown(); // FIRE!
        
        finishLatch.await(10, TimeUnit.SECONDS);
        requestPool.shutdown();
        return results;
    }

    private void analyzeResults(List<HttpResponse> attackResults, ProbeResult startProbe, ProbeResult endProbe) {
        if (attackResults.isEmpty()) {
            SwingUtilities.invokeLater(() -> {
                log("Error: No responses received.");
                setVerdict("FAILED", COLOR_NEUTRAL);
                JOptionPane.showMessageDialog(this, "No responses received.");
            });
            return;
        }

        // Calculate Baseline (Most common status)
        Map<Integer, Long> counts = attackResults.stream()
                .collect(Collectors.groupingBy(r -> (int) r.statusCode(), Collectors.counting()));
        
        int successStatus = -1;
        for(Integer code : counts.keySet()) if(code >= 200 && code < 400) { successStatus = code; break; }
        if (successStatus == -1) successStatus = Collections.max(counts.entrySet(), Map.Entry.comparingByValue()).getKey();
        
        final int finalStatus = successStatus;
        HttpResponse referenceResp = attackResults.stream().filter(r -> r.statusCode() == finalStatus).findFirst().orElse(attackResults.get(0));

        baselineStatus = finalStatus;
        baselineHash = calculateMD5(referenceResp.body());
        isErrorBase = (baselineStatus >= 400);

        List<HttpResponse> successes = attackResults.stream().filter(r -> r.statusCode() == baselineStatus).collect(Collectors.toList());
        long totalHttpSuccesses = successes.size(); 
        long uniqueHashes = successes.stream().map(r -> calculateMD5(r.body())).distinct().count(); 
        
        SwingUtilities.invokeLater(() -> {
            resultsTabs.setSelectedIndex(0);
            int id = 1;
            for(HttpResponse r : attackResults) {
                String currentHash = calculateMD5(r.body());
                boolean isExact = (r.statusCode() == baselineStatus && currentHash.equals(baselineHash));
                String note = isExact ? "Ref Match" : "Diff Body";
                if (r.statusCode() != baselineStatus) note = "Code " + r.statusCode();
                resultsModel.addRow(new Object[]{id++, r.statusCode(), r.body().length(), getShortHash(currentHash), note});
            }

            // --- RISK VERDICT LOGIC ---
            
            if (startProbe != null && endProbe != null) {
                log("    > Probe Analysis: " + startProbe.toString() + " -> " + endProbe.toString());
                int probeDiff = endProbe.count - startProbe.count;
                
                if (startProbe.isError || endProbe.isError) {
                     log("Probe error. Fallback to standard analysis.");
                }
                else {
                    // 1. CRITICAL: Multiple HTTP Successes AND Multiple Creations
                    if (totalHttpSuccesses > 1 && probeDiff > 1) {
                        setVerdict("CRITICAL (Duplication)", COLOR_VULNERABLE);
                        JOptionPane.showMessageDialog(this, 
                            "CRITICAL VULNERABILITY DETECTED!\n\n" +
                            "1. HTTP Layer: " + totalHttpSuccesses + " successful responses.\n" +
                            "2. Application State: " + probeDiff + " new resources created.\n\n" +
                            "This confirms a Race Condition with duplication.");
                        return;
                    }
                    
                    // 2. HIGH: HTTP Failures (or single success) BUT Multiple Creations (Hidden Race)
                    if (totalHttpSuccesses <= 1 && probeDiff > 1) {
                        setVerdict("HIGH (Silent Dupes)", COLOR_HIGH);
                        JOptionPane.showMessageDialog(this, 
                            "HIGH RISK ANOMALY DETECTED!\n\n" +
                            "1. HTTP Layer: Few or no successful responses.\n" +
                            "2. Application State: " + probeDiff + " new resources created (Duplication!).\n\n" +
                            "The server tried to block requests, but the database processed them anyway.");
                        return;
                    }
                    
                    // 3. MEDIUM/POTENTIAL: Multiple HTTP Successes but Normal Probe (<= 1 creation)
                    if (totalHttpSuccesses > 1 && probeDiff <= 1) {
                        setVerdict("MEDIUM (Idempotent?)", COLOR_MEDIUM);
                        JOptionPane.showMessageDialog(this, 
                            "POTENTIAL IDEMPOTENCY DETECTED\n\n" +
                            "1. HTTP Layer: " + totalHttpSuccesses + " successful responses (200 OK).\n" +
                            "2. Application State: " + probeDiff + " changes/creations.\n\n" +
                            "The server is accepting multiple requests in parallel.\n" +
                            "Since no duplicates were found, this is likely an Idempotent action (Safe),\n" +
                            "but you should verify if overwriting data is a risk.");
                        return;
                    }
                    
                    // 4. MEDIUM: State Change without Duplication (Update vs Create)
                    if (probeDiff == 0 && !startProbe.value.equals(endProbe.value)) {
                        setVerdict("MEDIUM (State Change)", COLOR_MEDIUM);
                        JOptionPane.showMessageDialog(this, "STATE CHANGE DETECTED (No Duplication).\nThe value changed, but count remained same.");
                        return;
                    }
                    
                    // 5. SAFE: 1 Success, 1 Creation (Normal behavior)
                    if (totalHttpSuccesses == 1 && probeDiff == 1) {
                        setVerdict("SAFE", COLOR_SAFE);
                        JOptionPane.showMessageDialog(this, "SAFE: Normal behavior (1 Request = 1 Creation).");
                        return;
                    }
                    
                    // 6. SAFE: Nothing happened
                    if (probeDiff == 0) {
                        setVerdict("SAFE (NO CHANGE)", COLOR_SAFE);
                        return;
                    }
                }
            }

            // Fallback (No Probe)
            if (isErrorBase) {
                 if (totalHttpSuccesses == attackResults.size()) {
                    setVerdict("FAILED (ALL " + baselineStatus + ")", COLOR_FAILED);
                    JOptionPane.showMessageDialog(this, 
                        "ATTACK FAILED (SAFE)\n\n" +
                        "All " + totalHttpSuccesses + " requests failed with status " + baselineStatus + ".\n\n" +
                        "No race condition possible if requests are invalid.\n" +
                        "Advice: Check your request body, headers, or cookies.");
                 } else {
                    setVerdict("UNSTABLE", COLOR_NEUTRAL);
                    JOptionPane.showMessageDialog(this, "UNSTABLE RESULTS\n\nMixed error codes received. No clear conclusion.");
                 }
            } else {
                if (totalHttpSuccesses <= 1) {
                    setVerdict("SAFE", COLOR_SAFE);
                    JOptionPane.showMessageDialog(this, "SAFE: Only 1 request succeeded.");
                } else if (uniqueHashes > 1) {
                    setVerdict("HIGH (Variation)", COLOR_HIGH); 
                    JOptionPane.showMessageDialog(this, 
                        "HIGH RISK DETECTED (VARIATION)\n\n" +
                        "Multiple requests succeeded (" + totalHttpSuccesses + ") and returned DIFFERENT content.\n" +
                        "This implies the server processed them distinctly.\n" +
                        "Manual verification recommended.");
                } else {
                    setVerdict("MEDIUM (Idempotent?)", COLOR_MEDIUM);
                    JOptionPane.showMessageDialog(this, 
                        "MEDIUM RISK (POTENTIAL IDEMPOTENCY)\n\n" +
                        "Multiple requests succeeded (" + totalHttpSuccesses + ") but returned IDENTICAL content.\n" +
                        "This is likely safe (Idempotent overwrites), but verify manually.");
                }
            }
        });
    }

    // --- UTILS & HELPERS ---
    
    private JButton createStyledButton(String text) {
        JButton btn = new JButton(text) {
            @Override
            protected void paintComponent(Graphics g) {
                Graphics2D g2 = (Graphics2D) g.create();
                g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
                g2.setColor(getBackground());
                g2.fillRoundRect(0, 0, getWidth(), getHeight(), 15, 15);
                super.paintComponent(g2);
                g2.dispose();
            }
        };
        btn.setFont(new Font("Segoe UI", Font.BOLD, 12));
        btn.setBackground(COLOR_ACCENT);
        btn.setForeground(Color.WHITE);
        btn.setFocusPainted(false);
        btn.setContentAreaFilled(false);
        btn.setBorderPainted(false);
        btn.setCursor(new Cursor(Cursor.HAND_CURSOR));
        btn.setPreferredSize(new Dimension(160, 35));
        return btn;
    }

    private void setupTableStyle(JTable table) {
        table.setRowHeight(30); 
        table.setFont(new Font("Segoe UI", Font.PLAIN, 12));
        table.setShowGrid(false); 
        table.setShowHorizontalLines(true); 
        table.setGridColor(new Color(230, 230, 230));
        table.setIntercellSpacing(new Dimension(0, 1));
        table.setFillsViewportHeight(true);
        
        JTableHeader header = table.getTableHeader();
        header.setFont(new Font("Segoe UI", Font.BOLD, 12));
        header.setBackground(Color.WHITE);
        header.setForeground(Color.GRAY);
        header.setPreferredSize(new Dimension(0, 30));
        
        table.setDefaultRenderer(Object.class, new RaceResultRenderer());
        table.getColumnModel().getColumn(0).setPreferredWidth(30);
        table.getColumnModel().getColumn(1).setPreferredWidth(50);
        table.getColumnModel().getColumn(3).setPreferredWidth(100);
    }
    
    private void setVerdict(String text, Color bg) {
        SwingUtilities.invokeLater(() -> { verdictLabel.setText(text); verdictLabel.setBackground(bg); });
    }
    private void setStatus(String msg, boolean isError) {
        SwingUtilities.invokeLater(() -> { statusLabel.setText(msg); statusLabel.setForeground(isError ? Color.RED : Color.GRAY); });
    }
    private String calculateMD5(ByteArray body) {
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] digest = md.digest(body.getBytes());
            StringBuilder sb = new StringBuilder();
            for (byte b : digest) sb.append(String.format("%02x", b));
            return sb.toString();
        } catch (Exception e) { return "HASH_ERR"; }
    }
    private String getShortHash(String hash) {
        if (hash == null || hash.length() < 8) return hash;
        return hash.substring(0, 8) + "...";
    }
    private void log(String msg) {
        SwingUtilities.invokeLater(() -> { logArea.append(msg + "\n"); logArea.setCaretPosition(logArea.getDocument().getLength()); });
        api.logging().logToOutput("[RaceUI] " + msg);
    }
    // Print full trace in visible log area for user
    private void logError(String msg, Throwable t) {
        StringWriter sw = new StringWriter(); t.printStackTrace(new PrintWriter(sw));
        String fullTrace = sw.toString();
        api.logging().logToError("[RaceUI ERROR] " + msg + "\n" + fullTrace);
        log("ERROR: " + msg);
        log("DETAILS: " + t.toString()); 
    }

    // --- RENDERER ---
    private class RaceResultRenderer extends DefaultTableCellRenderer {
        @Override
        public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int column) {
            Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
            if (c instanceof JLabel) ((JLabel) c).setBorder(new EmptyBorder(0, 5, 0, 5));
            if (!isSelected) {
                try {
                    Object statusObj = table.getValueAt(row, 1);
                    Object hashObj = table.getValueAt(row, 3); 
                    String baselineHashShort = getShortHash(baselineHash);
                    if (statusObj instanceof Integer && hashObj instanceof String) {
                        int status = (Integer) statusObj;
                        String currentHash = (String) hashObj;
                        boolean isExactMatch = (status == baselineStatus && currentHash.equals(baselineHashShort));
                        if (isExactMatch) {
                            if (isErrorBase) { c.setBackground(new Color(245, 245, 245)); c.setForeground(Color.DARK_GRAY); }
                            else { c.setBackground(new Color(240, 255, 240)); c.setForeground(new Color(39, 174, 96)); }
                        } else {
                            c.setBackground(new Color(255, 240, 240)); c.setForeground(new Color(192, 57, 43)); c.setFont(c.getFont().deriveFont(Font.BOLD));
                        }
                    }
                } catch (Exception e) { c.setBackground(Color.WHITE); }
            }
            return c;
        }
    }
}