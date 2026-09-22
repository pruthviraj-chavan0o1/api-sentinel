const API_BASE_URL = "";

// ============================================================
// API SENTINEL - FRONTEND CONTROLLER
// ============================================================
//
// Features:
// - JWT authentication
// - Protected API scanning
// - Vulnerability display
// - OWASP API Security findings
// - OWASP summary dashboard
// - Security score
// - Risk level
// - Scan history
// - Loading states
// - Error handling
// - HTML escaping
//
// ============================================================


// ============================================================
// LOGIN
// ============================================================

async function login() {

    const usernameInput =
        document.getElementById("username");

    const passwordInput =
        document.getElementById("password");

    const message =
        document.getElementById("loginMessage");

    const username =
        usernameInput.value.trim();

    const password =
        passwordInput.value;

    if (!username || !password) {

        showMessage(
            message,
            "⚠️ Please enter username and password.",
            "error"
        );

        return;
    }

    showMessage(
        message,
        "🔐 Authenticating...",
        "info"
    );

    try {

        const response =
            await fetch(
                `${API_BASE_URL}/api/auth/login`,
                {
                    method: "POST",

                    headers: {
                        "Content-Type":
                            "application/json"
                    },

                    body: JSON.stringify({
                        username,
                        password
                    })
                }
            );

        const result =
            await parseJsonResponse(response);

        if (!response.ok) {

            showMessage(
                message,
                result.message ||
                    "Invalid username or password.",
                "error"
            );

            return;
        }

        if (!result.token) {

            showMessage(
                message,
                "Login response did not contain a token.",
                "error"
            );

            return;
        }

        localStorage.setItem(
            "apiSentinelToken",
            result.token
        );

        localStorage.setItem(
            "apiSentinelUsername",
            result.username || username
        );

        showMessage(
            message,
            `✓ Login successful. Welcome ${escapeHtml(
                result.username || username
            )}!`,
            "success"
        );

        passwordInput.value = "";

        updateLoginState(
            result.username || username
        );

        await loadHistory();

    } catch (error) {

        console.error(
            "Login error:",
            error
        );

        showMessage(
            message,
            "❌ Unable to connect to API Sentinel.",
            "error"
        );
    }
}


// ============================================================
// LOGOUT
// ============================================================

function logout() {

    localStorage.removeItem(
        "apiSentinelToken"
    );

    localStorage.removeItem(
        "apiSentinelUsername"
    );

    const loginMessage =
        document.getElementById("loginMessage");

    if (loginMessage) {

        showMessage(
            loginMessage,
            "✓ Logged out successfully.",
            "success"
        );
    }

    const historyContainer =
        document.getElementById(
            "historyContainer"
        );

    if (historyContainer) {

        historyContainer.innerHTML = `
            <div class="empty-state">

                <div class="empty-icon">
                    🔐
                </div>

                <h3>
                    Authentication Required
                </h3>

                <p>
                    Login to load your scan history.
                </p>

            </div>
        `;
    }

    const totalScans =
        document.getElementById(
            "totalScans"
        );

    if (totalScans) {

        totalScans.textContent =
            "--";
    }

    const securityScore =
        document.getElementById(
            "securityScore"
        );

    if (securityScore) {

        securityScore.textContent =
            "--";
    }

    const riskLevel =
        document.getElementById(
            "riskLevel"
        );

    if (riskLevel) {

        riskLevel.textContent =
            "--";

        riskLevel.style.color =
            "";
    }
}


// ============================================================
// GET JWT TOKEN
// ============================================================

function getToken() {

    return localStorage.getItem(
        "apiSentinelToken"
    );
}


// ============================================================
// GET USERNAME
// ============================================================

function getUsername() {

    return localStorage.getItem(
        "apiSentinelUsername"
    );
}


// ============================================================
// AUTHORIZATION HEADERS
// ============================================================

function getAuthHeaders() {

    const token =
        getToken();

    return {
        "Authorization":
            `Bearer ${token}`
    };
}


// ============================================================
// SCAN API
// ============================================================

async function scanApi() {

    const urlInput =
        document.getElementById(
            "apiUrl"
        );

    const message =
        document.getElementById(
            "scanMessage"
        );

    if (!urlInput || !message) {
        return;
    }

    const url =
        urlInput.value.trim();

    if (!url) {

        showMessage(
            message,
            "⚠️ Please enter an API URL.",
            "error"
        );

        urlInput.focus();

        return;
    }

    let parsedUrl;

    try {

        parsedUrl =
            new URL(url);

    } catch (error) {

        showMessage(
            message,
            "❌ Please enter a valid URL.",
            "error"
        );

        return;
    }

    if (
        parsedUrl.protocol !== "http:" &&
        parsedUrl.protocol !== "https:"
    ) {

        showMessage(
            message,
            "❌ Only HTTP and HTTPS URLs are supported.",
            "error"
        );

        return;
    }

    const token =
        getToken();

    if (!token) {

        showMessage(
            message,
            "🔐 Please login before scanning an API.",
            "error"
        );

        return;
    }

    setScanLoading(true);

    showMessage(
        message,
        "🔍 Scanning API security configuration...",
        "info"
    );

    try {

        const response =
            await fetch(
                `${API_BASE_URL}/api/scanner/scan?url=${encodeURIComponent(
                    url
                )}`,
                {
                    method: "POST",

                    headers:
                        getAuthHeaders()
                }
            );

        if (
            response.status === 401 ||
            response.status === 403
        ) {

            handleUnauthorized();

            return;
        }

        const result =
            await parseJsonResponse(
                response
            );

        if (
            response.ok &&
            result.status ===
                "SCAN_COMPLETED"
        ) {

            showMessage(
                message,
                "✓ Security scan completed successfully.",
                "success"
            );

            displayLatestResult(
                result
            );

            await loadHistory();

        } else {

            showMessage(
                message,
                "❌ Scan failed: " +
                    (
                        result.error ||
                        "Unknown scanner error."
                    ),
                "error"
            );
        }

    } catch (error) {

        console.error(
            "Scanner error:",
            error
        );

        showMessage(
            message,
            "❌ Unable to connect to API Sentinel.",
            "error"
        );

    } finally {

        setScanLoading(
            false
        );
    }
}


// ============================================================
// DISPLAY LATEST SCAN RESULT
// ============================================================

function displayLatestResult(
    result
) {

    const container =
        document.getElementById(
            "latestResult"
        );

    if (!container) {
        return;
    }

    const vulnerabilities =
        Array.isArray(
            result.vulnerabilities
        )
            ? result.vulnerabilities
            : [];

    const presentHeaders =
        Array.isArray(
            result.securityHeadersPresent
        )
            ? result.securityHeadersPresent
            : [];

    const missingHeaders =
        Array.isArray(
            result.securityHeadersMissing
        )
            ? result.securityHeadersMissing
            : [];

    const owaspFindings =
        Array.isArray(
            result.owaspFindings
        )
            ? result.owaspFindings
            : [];

    const owaspFindingCount =
        result.owaspFindingCount !==
        undefined
            ? result.owaspFindingCount
            : owaspFindings.length;


    // ========================================================
    // OWASP SUMMARY COUNTS
    // ========================================================

    const owaspSummary = {

        detected: 0,

        potential: 0,

        notDetected: 0,

        notTestable: 0
    };


    owaspFindings.forEach(
        finding => {

            const status =
                String(
                    finding.status ||
                        ""
                ).toUpperCase();

            if (
                status ===
                "DETECTED"
            ) {

                owaspSummary.detected++;
            }

            else if (
                status ===
                "POTENTIAL"
            ) {

                owaspSummary.potential++;
            }

            else if (
                status ===
                "NOT_DETECTED"
            ) {

                owaspSummary.notDetected++;
            }

            else if (
                status ===
                "NOT_TESTABLE"
            ) {

                owaspSummary.notTestable++;
            }
        }
    );


    // ========================================================
    // OWASP SUMMARY HTML
    // ========================================================

    const owaspSummaryHtml = `

        <div class="owasp-summary">

            <div class="owasp-summary-card detected">

                <span class="owasp-summary-icon">
                    🔴
                </span>

                <div>

                    <strong>
                        ${owaspSummary.detected}
                    </strong>

                    <span>
                        Detected
                    </span>

                </div>

            </div>


            <div class="owasp-summary-card potential">

                <span class="owasp-summary-icon">
                    🟡
                </span>

                <div>

                    <strong>
                        ${owaspSummary.potential}
                    </strong>

                    <span>
                        Potential
                    </span>

                </div>

            </div>


            <div class="owasp-summary-card safe">

                <span class="owasp-summary-icon">
                    🟢
                </span>

                <div>

                    <strong>
                        ${owaspSummary.notDetected}
                    </strong>

                    <span>
                        Not Detected
                    </span>

                </div>

            </div>


            <div class="owasp-summary-card not-testable">

                <span class="owasp-summary-icon">
                    ⚪
                </span>

                <div>

                    <strong>
                        ${owaspSummary.notTestable}
                    </strong>

                    <span>
                        Not Testable
                    </span>

                </div>

            </div>

        </div>
    `;


    // ========================================================
    // OWASP FINDINGS HTML
    // ========================================================

    let owaspHtml = "";

    if (
        owaspFindings.length === 0
    ) {

        owaspHtml = `

            <div class="no-vulnerabilities">

                <div class="finding-icon">
                    ✓
                </div>

                <div>

                    <strong>
                        No OWASP findings available
                    </strong>

                    <p>
                        The scanner did not return
                        any OWASP API Security findings.
                    </p>

                </div>

            </div>
        `;

    } else {

        owaspHtml =
            owaspFindings
                .map(
                    (
                        finding,
                        index
                    ) => {

                        const status =
                            finding.status ||
                            "UNKNOWN";

                        const severity =
                            finding.severity ||
                            "INFO";

                        return `

                            <div class="owasp-card ${getOwaspStatusClass(
                                status
                            )}">

                                <div class="owasp-card-header">

                                    <div>

                                        <span class="owasp-category">

                                            ${escapeHtml(
                                                finding.category ||
                                                    "OWASP API Security"
                                            )}

                                        </span>

                                        <h4>

                                            ${index + 1}.
                                            ${escapeHtml(
                                                finding.title ||
                                                    "Security Finding"
                                            )}

                                        </h4>

                                    </div>


                                    <div class="owasp-badges">

                                        <span class="badge ${getRiskClass(
                                            severity
                                        )}">

                                            ${escapeHtml(
                                                severity
                                            )}

                                        </span>


                                        <span class="badge owasp-status-badge">

                                            ${escapeHtml(
                                                status
                                            )}

                                        </span>

                                    </div>

                                </div>


                                <p class="owasp-description">

                                    ${escapeHtml(
                                        finding.description ||
                                            "No description available."
                                    )}

                                </p>


                                <div class="owasp-recommendation">

                                    <strong>
                                        💡 Recommendation
                                    </strong>

                                    <p>

                                        ${escapeHtml(
                                            finding.recommendation ||
                                                "Review this OWASP category manually."
                                        )}

                                    </p>

                                </div>

                            </div>
                        `;
                    }
                )
                .join("");
    }


    // ========================================================
    // VULNERABILITY HTML
    // ========================================================

    const vulnerabilityCount =
        result.vulnerabilityCount !==
        undefined
            ? result.vulnerabilityCount
            : vulnerabilities.length;

    let vulnerabilityHtml = "";

    if (
        vulnerabilities.length === 0
    ) {

        vulnerabilityHtml = `

            <div class="no-vulnerabilities">

                <div class="finding-icon">
                    ✓
                </div>

                <div>

                    <strong>
                        No vulnerabilities detected
                    </strong>

                    <p>
                        The scanner did not identify
                        any configured security findings.
                    </p>

                </div>

            </div>
        `;

    } else {

        vulnerabilityHtml =
            vulnerabilities
                .map(
                    (
                        vulnerability,
                        index
                    ) => {

                        const severity =
                            vulnerability.severity ||
                            "UNKNOWN";

                        return `

                            <div class="vulnerability-card">

                                <div class="vulnerability-header">

                                    <div class="vulnerability-number">
                                        ${index + 1}
                                    </div>


                                    <div class="vulnerability-main">

                                        <div class="vulnerability-title-row">

                                            <h4>

                                                ${escapeHtml(
                                                    vulnerability.title ||
                                                        "Security Finding"
                                                )}

                                            </h4>


                                            <span class="badge ${getRiskClass(
                                                severity
                                            )}">

                                                ${escapeHtml(
                                                    severity
                                                )}

                                            </span>

                                        </div>


                                        <p class="vulnerability-description">

                                            ${escapeHtml(
                                                vulnerability.description ||
                                                    "No description available."
                                            )}

                                        </p>

                                    </div>

                                </div>


                                <div class="recommendation">

                                    <strong>
                                        💡 Recommendation
                                    </strong>

                                    <p>

                                        ${escapeHtml(
                                            vulnerability.recommendation ||
                                                "Review the API security configuration."
                                        )}

                                    </p>

                                </div>

                            </div>
                        `;
                    }
                )
                .join("");
    }


    // ========================================================
    // COMPLETE RESULT
    // ========================================================

    container.innerHTML = `

        <!-- SUMMARY -->

        <div class="scan-result-header">

            <div>

                <span class="section-label">
                    SCAN COMPLETED
                </span>

                <h3>
                    Security Assessment
                </h3>

                <p>
                    ${escapeHtml(
                        result.url
                    )}
                </p>

            </div>


            <div class="scan-result-status">

                <span class="status-dot"></span>

                COMPLETED

            </div>

        </div>


        <!-- RESULT GRID -->

        <div class="result-grid">

            <div class="result-item">

                <strong>
                    🌐 URL
                </strong>

                <span>
                    ${escapeHtml(
                        result.url
                    )}
                </span>

            </div>


            <div class="result-item">

                <strong>
                    📡 Method
                </strong>

                <span>
                    ${escapeHtml(
                        result.method
                    )}
                </span>

            </div>


            <div class="result-item">

                <strong>
                    📊 Status Code
                </strong>

                <span>
                    ${result.statusCode}
                </span>

            </div>


            <div class="result-item">

                <strong>
                    ⚡ Response Time
                </strong>

                <span>
                    ${result.responseTimeMs} ms
                </span>

            </div>


            <div class="result-item">

                <strong>
                    🎯 Security Score
                </strong>

                <span class="result-score">
                    ${result.securityScore}/100
                </span>

            </div>


            <div class="result-item">

                <strong>
                    ⚠️ Risk Level
                </strong>

                <span class="badge ${getRiskClass(
                    result.riskLevel
                )}">

                    ${escapeHtml(
                        result.riskLevel ||
                            "UNKNOWN"
                    )}

                </span>

            </div>


            <div class="result-item">

                <strong>
                    📄 Content Type
                </strong>

                <span>
                    ${escapeHtml(
                        result.contentType
                    )}
                </span>

            </div>


            <div class="result-item">

                <strong>
                    🖥️ Server
                </strong>

                <span>
                    ${escapeHtml(
                        result.server
                    )}
                </span>

            </div>


            <div class="result-item">

                <strong>
                    📦 Response Size
                </strong>

                <span>
                    ${result.responseSize} bytes
                </span>

            </div>


            <div class="result-item">

                <strong>
                    🆔 Scan ID
                </strong>

                <span>
                    #${result.scanId}
                </span>

            </div>

        </div>


        <!-- SECURITY HEADERS -->

        <div class="headers-section">

            <h3>
                🛡️ Security Headers
            </h3>


            <div class="headers-grid">

                <div class="headers-box present">

                    <div class="headers-box-title">

                        <span>
                            ✓
                        </span>

                        Present

                    </div>


                    <div class="header-list">

                        ${
                            presentHeaders.length > 0

                                ? presentHeaders
                                    .map(
                                        header => `

                                            <span class="header-tag">

                                                ✓
                                                ${escapeHtml(
                                                    header
                                                )}

                                            </span>
                                        `
                                    )
                                    .join("")

                                : `

                                    <span class="header-empty">
                                        None detected
                                    </span>

                                `
                        }

                    </div>

                </div>


                <div class="headers-box missing">

                    <div class="headers-box-title">

                        <span>
                            !
                        </span>

                        Missing

                    </div>


                    <div class="header-list">

                        ${
                            missingHeaders.length > 0

                                ? missingHeaders
                                    .map(
                                        header => `

                                            <span class="header-tag">

                                                !
                                                ${escapeHtml(
                                                    header
                                                )}

                                            </span>
                                        `
                                    )
                                    .join("")

                                : `

                                    <span class="header-empty">
                                        None
                                    </span>

                                `
                        }

                    </div>

                </div>

            </div>

        </div>


        <!-- OWASP API SECURITY -->

        <div class="owasp-section">

            <div class="vulnerability-section-header">

                <div>

                    <span class="section-label">
                        OWASP API SECURITY TOP 10
                    </span>

                    <h3>
                        OWASP Security Assessment
                    </h3>

                    <p>

                        ${owaspFindingCount}
                        OWASP checks returned by the scanner.

                    </p>

                </div>


                <div class="vulnerability-count">

                    ${owaspFindingCount}

                </div>

            </div>


            <!-- OWASP SUMMARY CARDS -->

            ${owaspSummaryHtml}


            <!-- OWASP FINDINGS -->

            <div class="owasp-list">

                ${owaspHtml}

            </div>

        </div>


        <!-- VULNERABILITIES -->

        <div class="vulnerability-section">

            <div class="vulnerability-section-header">

                <div>

                    <span class="section-label">
                        SECURITY FINDINGS
                    </span>

                    <h3>
                        Vulnerabilities Detected
                    </h3>

                </div>


                <div class="vulnerability-count">

                    ${vulnerabilityCount}

                </div>

            </div>


            <div class="vulnerability-list">

                ${vulnerabilityHtml}

            </div>

        </div>

    `;

    updateDashboardStats(
        result
    );
}


// ============================================================
// UPDATE DASHBOARD STATS
// ============================================================

function updateDashboardStats(
    result
) {

    const scoreElement =
        document.getElementById(
            "securityScore"
        );

    const riskElement =
        document.getElementById(
            "riskLevel"
        );

    if (scoreElement) {

        scoreElement.textContent =
            result.securityScore !==
            undefined
                ? result.securityScore
                : "--";
    }

    if (riskElement) {

        riskElement.textContent =
            result.riskLevel ||
            "--";

        riskElement.style.color =
            getRiskColor(
                result.riskLevel
            );
    }
}


// ============================================================
// LOAD SCAN HISTORY
// ============================================================

async function loadHistory() {

    const container =
        document.getElementById(
            "historyContainer"
        );

    const totalScans =
        document.getElementById(
            "totalScans"
        );

    if (!container) {
        return;
    }

    const token =
        getToken();

    if (!token) {

        if (totalScans) {

            totalScans.textContent =
                "--";
        }

        container.innerHTML = `

            <div class="empty-state">

                <div class="empty-icon">
                    🔐
                </div>

                <h3>
                    Authentication Required
                </h3>

                <p>
                    Login to load your scan history.
                </p>

            </div>
        `;

        return;
    }

    container.innerHTML = `

        <div class="loading-state">

            <div class="loading-spinner"></div>

            <p>
                Loading scan history...
            </p>

        </div>
    `;

    try {

        const response =
            await fetch(
                `${API_BASE_URL}/api/scanner/history`,
                {
                    method: "GET",

                    headers:
                        getAuthHeaders()
                }
            );

        if (
            response.status === 401 ||
            response.status === 403
        ) {

            handleUnauthorized();

            return;
        }

        const history =
            await parseJsonResponse(
                response
            );

        if (!response.ok) {

            throw new Error(
                "Unable to load scan history."
            );
        }

        const scans =
            Array.isArray(history)
                ? history
                : [];

        if (totalScans) {

            totalScans.textContent =
                scans.length;
        }

        if (scans.length === 0) {

            container.innerHTML = `

                <div class="empty-state">

                    <div class="empty-icon">
                        📊
                    </div>

                    <h3>
                        No Scan History
                    </h3>

                    <p>
                        Your completed API security
                        scans will appear here.
                    </p>

                </div>
            `;

            return;
        }

        let table = `

            <div class="table-wrapper">

                <table class="history-table">

                    <thead>

                        <tr>

                            <th>
                                ID
                            </th>

                            <th>
                                API Endpoint
                            </th>

                            <th>
                                Status
                            </th>

                            <th>
                                Score
                            </th>

                            <th>
                                Risk
                            </th>

                            <th>
                                Scanned At
                            </th>

                        </tr>

                    </thead>


                    <tbody>
        `;


        scans.forEach(
            scan => {

                table += `

                    <tr>

                        <td>

                            <span class="scan-id">
                                #${scan.id}
                            </span>

                        </td>


                        <td>

                            <span
                                class="history-url"
                                title="${escapeHtml(
                                    scan.url
                                )}"
                            >

                                ${escapeHtml(
                                    shortenUrl(
                                        scan.url
                                    )
                                )}

                            </span>

                        </td>


                        <td>

                            <span
                                class="status-code ${getStatusClass(
                                    scan.statusCode
                                )}"
                            >

                                ${scan.statusCode}

                            </span>

                        </td>


                        <td>

                            <strong>

                                ${scan.securityScore}/100

                            </strong>

                        </td>


                        <td>

                            <span class="badge ${getRiskClass(
                                scan.riskLevel
                            )}">

                                ${escapeHtml(
                                    scan.riskLevel ||
                                        "UNKNOWN"
                                )}

                            </span>

                        </td>


                        <td>

                            ${formatDate(
                                scan.scannedAt
                            )}

                        </td>

                    </tr>
                `;
            }
        );


        table += `

                    </tbody>

                </table>

            </div>
        `;

        container.innerHTML =
            table;

        if (scans.length > 0) {

            updateDashboardStats(
                scans[0]
            );
        }

    } catch (error) {

        console.error(
            "History error:",
            error
        );

        container.innerHTML = `

            <div class="empty-state">

                <div class="empty-icon">
                    ⚠️
                </div>

                <h3>
                    Unable to Load History
                </h3>

                <p>
                    Please refresh the dashboard
                    and try again.
                </p>

            </div>
        `;
    }
}


// ============================================================
// HANDLE UNAUTHORIZED
// ============================================================

function handleUnauthorized() {

    localStorage.removeItem(
        "apiSentinelToken"
    );

    localStorage.removeItem(
        "apiSentinelUsername"
    );

    const scanMessage =
        document.getElementById(
            "scanMessage"
        );

    if (scanMessage) {

        showMessage(
            scanMessage,
            "🔐 Session expired. Please login again.",
            "error"
        );
    }

    const loginMessage =
        document.getElementById(
            "loginMessage"
        );

    if (loginMessage) {

        showMessage(
            loginMessage,
            "🔐 Please login to continue.",
            "error"
        );
    }
}


// ============================================================
// UPDATE LOGIN STATE
// ============================================================

function updateLoginState(
    username
) {

    const loginSection =
        document.getElementById(
            "loginSection"
        );

    if (!loginSection) {
        return;
    }

    const heading =
        loginSection.querySelector(
            "h2"
        );

    if (heading) {

        heading.innerHTML =
            "🔐 Authentication Active";
    }

    const description =
        loginSection.querySelector(
            ".description"
        );

    if (description) {

        description.textContent =
            `Authenticated as ${username}. You can now scan authorized APIs.`;
    }
}


// ============================================================
// SET SCAN LOADING STATE
// ============================================================

function setScanLoading(
    isLoading
) {

    const buttons =
        document.querySelectorAll(
            ".scan-button, button[onclick='scanApi()']"
        );

    buttons.forEach(
        button => {

            if (isLoading) {

                button.disabled =
                    true;

                button.dataset.originalText =
                    button.innerHTML;

                button.innerHTML =
                    "⏳ SCANNING...";

            } else {

                button.disabled =
                    false;

                button.innerHTML =
                    button.dataset.originalText ||
                    "🔍 SCAN API";
            }
        }
    );
}


// ============================================================
// MESSAGE HELPER
// ============================================================

function showMessage(
    element,
    message,
    type
) {

    if (!element) {
        return;
    }

    element.innerHTML =
        message;

    switch (type) {

        case "success":

            element.style.color =
                "#4ade80";

            break;

        case "error":

            element.style.color =
                "#f87171";

            break;

        case "info":

            element.style.color =
                "#38bdf8";

            break;

        default:

            element.style.color =
                "#e5e7eb";
    }
}


// ============================================================
// OWASP STATUS CLASS
// ============================================================

function getOwaspStatusClass(
    status
) {

    if (!status) {
        return "";
    }

    switch (
        String(status)
            .toUpperCase()
    ) {

        case "DETECTED":

            return "owasp-detected";

        case "POTENTIAL":

            return "owasp-potential";

        case "NOT_DETECTED":

            return "owasp-safe";

        case "NOT_TESTABLE":

            return "owasp-not-testable";

        default:

            return "";
    }
}


// ============================================================
// RISK CLASS
// ============================================================

function getRiskClass(
    risk
) {

    if (!risk) {
        return "";
    }

    switch (
        String(risk)
            .toUpperCase()
    ) {

        case "LOW":

            return "badge-low";

        case "MEDIUM":

            return "badge-medium";

        case "HIGH":

            return "badge-high";

        case "CRITICAL":

            return "badge-critical";

        case "INFO":

            return "badge-info";

        default:

            return "";
    }
}


// ============================================================
// RISK COLOR
// ============================================================

function getRiskColor(
    risk
) {

    if (!risk) {

        return "#e5e7eb";
    }

    switch (
        String(risk)
            .toUpperCase()
    ) {

        case "LOW":

            return "#4ade80";

        case "MEDIUM":

            return "#facc15";

        case "HIGH":

            return "#f87171";

        case "CRITICAL":

            return "#ef4444";

        case "INFO":

            return "#38bdf8";

        default:

            return "#e5e7eb";
    }
}


// ============================================================
// HTTP STATUS CLASS
// ============================================================

function getStatusClass(
    statusCode
) {

    const status =
        Number(statusCode);

    if (
        status >= 200 &&
        status < 300
    ) {

        return "status-success";
    }

    if (
        status >= 300 &&
        status < 400
    ) {

        return "status-redirect";
    }

    if (
        status >= 400 &&
        status < 500
    ) {

        return "status-client-error";
    }

    if (status >= 500) {

        return "status-server-error";
    }

    return "";
}


// ============================================================
// FORMAT DATE
// ============================================================

function formatDate(
    dateString
) {

    if (!dateString) {
        return "-";
    }

    const date =
        new Date(
            dateString
        );

    if (
        Number.isNaN(
            date.getTime()
        )
    ) {

        return "-";
    }

    return date.toLocaleString();
}


// ============================================================
// SHORTEN URL
// ============================================================

function shortenUrl(
    url
) {

    if (!url) {
        return "-";
    }

    const maxLength =
        55;

    if (
        String(url).length <=
        maxLength
    ) {

        return String(url);
    }

    return (
        String(url).substring(
            0,
            maxLength
        ) + "..."
    );
}


// ============================================================
// HTML ESCAPING
// ============================================================

function escapeHtml(
    value
) {

    if (
        value === null ||
        value === undefined
    ) {

        return "";
    }

    return String(value)
        .replaceAll(
            "&",
            "&amp;"
        )
        .replaceAll(
            "<",
            "&lt;"
        )
        .replaceAll(
            ">",
            "&gt;"
        )
        .replaceAll(
            '"',
            "&quot;"
        )
        .replaceAll(
            "'",
            "&#039;"
        );
}


// ============================================================
// SAFE JSON RESPONSE
// ============================================================

async function parseJsonResponse(
    response
) {

    const text =
        await response.text();

    if (!text) {
        return {};
    }

    try {

        return JSON.parse(
            text
        );

    } catch (error) {

        return {
            message: text
        };
    }
}


// ============================================================
// ENTER KEY SUPPORT - LOGIN
// ============================================================

document.addEventListener(
    "DOMContentLoaded",
    function () {

        const passwordElement =
            document.getElementById(
                "password"
            );

        if (passwordElement) {

            passwordElement.addEventListener(
                "keydown",
                function (event) {

                    if (
                        event.key ===
                        "Enter"
                    ) {

                        login();
                    }
                }
            );
        }


        // ====================================================
        // ENTER KEY SUPPORT - API URL
        // ====================================================

        const apiUrlElement =
            document.getElementById(
                "apiUrl"
            );

        if (apiUrlElement) {

            apiUrlElement.addEventListener(
                "keydown",
                function (event) {

                    if (
                        event.key ===
                        "Enter"
                    ) {

                        scanApi();
                    }
                }
            );
        }


        // ====================================================
        // INITIALIZE DASHBOARD
        // ====================================================

        const token =
            getToken();

        if (token) {

            const username =
                getUsername();

            if (username) {

                updateLoginState(
                    username
                );
            }

            loadHistory();

        } else {

            loadHistory();
        }
    }
);