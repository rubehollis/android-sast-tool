import React, { useState, useEffect } from 'react';
import JSZip from 'jszip'; // For reading APK as a zip file

// Main App component for the SAST tool
const App = () => {
    // State variables
    const [apkFile, setApkFile] = useState(null); // Stores the selected APK file
    const [manifestContent, setManifestContent] = useState(''); // Stores the manually pasted AndroidManifest.xml content
    const [analysisResults, setAnalysisResults] = useState([]); // Stores the SAST findings
    const [isLoading, setIsLoading] = useState(false); // Indicates if analysis is in progress
    const [error, setError] = useState(''); // Stores any error messages
    const [showInstructions, setShowInstructions] = useState(true); // Controls visibility of initial instructions
    const [darkMode, setDarkMode] = useState(false); // New state for dark mode: false (light) or true (dark)
    const [isOptionsExpanded, setIsOptionsExpanded] = useState(false); // Controls the collapse/expand state of analysis options

    // Analysis toggles state variables
    const [enableDebuggableCheck, setEnableDebuggableCheck] = useState(true);
    const [enableAllowBackupCheck, setEnableAllowBackupCheck] = useState(true);
    const [enableCleartextCheck, setEnableCleartextCheck] = useState(true);
    const [enableExportedCheck, setEnableExportedCheck] = useState(true);
    const [enablePermissionCheck, setEnablePermissionCheck] = useState(true);
    const [enableTargetSdkVersionCheck, setEnableTargetSdkVersionCheck] = useState(true);
    const [enableHardcodedSecretCheck, setEnableHardcodedSecretCheck] = useState(true);
    const [enableDeepLinkCheck, setEnableDeepLinkCheck] = useState(true);
    const [enableSharedUserIdCheck, setEnableSharedUserIdCheck] = useState(true);
    const [enableImplicitIntentCheck, setEnableImplicitIntentCheck] = useState(true);
    const [enableSeparateProcessCheck, setEnableSeparateProcessCheck] = useState(true);
    const [enableMinSdkVersionCheck, setEnableMinSdkVersionCheck] = useState(true);
    const [enableCustomPermissionCheck, setEnableCustomPermissionCheck] = useState(true);
    const [enableTestOnlyCheck, setEnableTestOnlyCheck] = useState(true);
    const [enableFullBackupContentCheck, setEnableFullBackupContentCheck] = useState(true);
    const [enableTaskAffinityCheck, setEnableTaskAffinityCheck] = useState(true);
    const [enableInsecureDeepLinkSchemeCheck, setEnableInsecureDeepLinkSchemeCheck] = useState(true);
    const [enableBackupAgentCheck, setEnableBackupAgentCheck] = useState(true);
    const [enableAllowTaskReparentingCheck, setEnableAllowTaskReparentingCheck] = useState(true);
    const [enableAllowClearUserDataCheck, setEnableAllowClearUserDataCheck] = useState(true);
    const [enableSensitiveProcessNameCheck, setEnableSensitiveProcessNameCheck] = useState(true);
    const [enableExtractNativeLibsCheck, setEnableExtractNativeLibsCheck] = useState(true);
    const [enableOptionalLibraryCheck, setEnableOptionalLibraryCheck] = useState(true);
    const [enableProtectionLevelDangerousCheck, setEnableProtectionLevelDangerousCheck] = useState(true);
    const [enableHardwareAcceleratedCheck, setEnableHardwareAcceleratedCheck] = useState(true);
    const [enableFullscreenThemeCheck, setEnableFullscreenThemeCheck] = useState(true);
    const [enableUsesFeatureCheck, setEnableUsesFeatureCheck] = useState(true);
    const [enableGrantUriPermissionsCheck, setEnableGrantUriPermissionsCheck] = useState(true);


    // --- Theme Variables (Hardcoded for Black & Teal) ---
    const mainBackground = darkMode ? 'bg-gray-900 text-gray-100' : 'bg-gray-50 text-gray-900';
    const cardBackground = darkMode ? 'bg-gray-800 card' : 'bg-white card';
    const headerTextColor = darkMode ? 'text-teal-400' : 'text-gray-800';
    const buttonGradient = 'from-teal-500 via-cyan-500 to-teal-500';
    const fileButtonClass = 'file:bg-teal-50 file:text-teal-700 hover:file:bg-teal-100 dark:file:bg-teal-600 dark:file:text-white dark:hover:file:bg-teal-500';
    const instructionsBg = 'bg-gray-100 border-gray-300 text-gray-800 dark:bg-gray-800 dark:border-gray-600 dark:text-gray-200';
    const errorBg = 'bg-red-100 border-red-400 text-red-700 dark:bg-red-900 dark:border-red-700 dark:text-red-100';
    const optionsBg = 'bg-gray-200 dark:bg-gray-700';
    const toggleBgChecked = 'bg-teal-500'; // Color for the toggle switch when checked
    const toggleBgUnchecked = 'bg-gray-200 dark:bg-gray-600';


    // Function to handle APK file selection
    const handleFileChange = (event) => {
        const file = event.target.files[0];
        if (file && file.name.endsWith('.apk')) {
            setApkFile(file);
            setError('');
            setManifestContent(''); // Clear previous manifest content
            setAnalysisResults([]); // Clear previous results
            setShowInstructions(false); // Hide instructions once file is selected
        } else {
            setApkFile(null);
            setError('Please select a valid .apk file.');
            setManifestContent('');
            setAnalysisResults([]);
        }
    };

    // Function to handle manifest content changes (user pasting XML)
    const handleManifestChange = (event) => {
        setManifestContent(event.target.value);
    };

    // Function to perform the SAST analysis
    const performAnalysis = async () => {
        if (!manifestContent.trim()) {
            setError('Please paste the content of your AndroidManifest.xml to analyze.');
            return;
        }

        setIsLoading(true);
        setError('');
        setAnalysisResults([]);

        try {
            const findings = analyzeManifest(manifestContent);
            setAnalysisResults(findings);
        } catch (err) {
            console.error('Analysis error:', err);
            setError('An error occurred during analysis. Please check your XML format.');
        } finally {
            setIsLoading(false);
        }
    };

    // Helper function to analyze the AndroidManifest.xml content
    const analyzeManifest = (xmlString) => {
        const parser = new DOMParser();
        const xmlDoc = parser.parseFromString(xmlString, "text/xml");
        const findings = [];

        // Check for XML parsing errors
        if (xmlDoc.getElementsByTagName("parsererror").length > 0) {
            findings.push({
                severity: "Error",
                description: "Invalid XML provided. Please ensure it's well-formed.",
                recommendation: "Check your AndroidManifest.xml for syntax errors. You can use an online XML validator to ensure correctness."
            });
            return findings;
        }

        const applicationTag = xmlDoc.getElementsByTagName("application")[0];
        const manifestTag = xmlDoc.getElementsByTagName("manifest")[0];
        const usesSdkTag = xmlDoc.getElementsByTagName("uses-sdk")[0];


        if (manifestTag) {
            // --- Check for sharedUserId (if enabled) ---
            if (enableSharedUserIdCheck) {
                const sharedUserId = manifestTag.getAttribute("android:sharedUserId");
                if (sharedUserId) {
                    findings.push({
                        severity: "High",
                        description: `The manifest uses \`android:sharedUserId="${sharedUserId}"\`.`,
                        recommendation: "Using `sharedUserId` allows two or more apps to share the same Linux user ID and run in the same process. This means they can access each other's data and run with the same permissions. Avoid using this unless absolutely necessary, as a vulnerability in one app can compromise the others."
                    });
                }
            }

            // --- Check for `minSdkVersion` and `targetSdkVersion` misconfiguration (if enabled) ---
            if (enableMinSdkVersionCheck || enableTargetSdkVersionCheck) {
                let minSdkVersion = 0;
                let targetSdkVersion = 0;

                // Priority for uses-sdk tag
                if (usesSdkTag) {
                    minSdkVersion = parseInt(usesSdkTag.getAttribute("android:minSdkVersion"), 10);
                    targetSdkVersion = parseInt(usesSdkTag.getAttribute("android:targetSdkVersion"), 10);
                } else if (manifestTag) {
                    // Fallback to manifest tag for targetSdkVersion if uses-sdk is missing
                    targetSdkVersion = parseInt(manifestTag.getAttribute("android:targetSdkVersion"), 10);
                }
                
                if (enableMinSdkVersionCheck && minSdkVersion > 0 && minSdkVersion < 21) {
                     findings.push({
                        severity: "High",
                        description: `The app targets a very old minimum SDK version (${minSdkVersion}).`,
                        recommendation: "Setting a low `minSdkVersion` can expose your app to a wide range of legacy vulnerabilities and an insecure security model. It's recommended to set the `minSdkVersion` to at least 21 (Lollipop) to benefit from crucial security features like `SELinux` enforcing, `forbid-cleartext-traffic`, and more robust IPC protections."
                    });
                }

                if (enableTargetSdkVersionCheck) {
                    const minimumRecommendedVersion = 29; // Android 10
                    if (isNaN(targetSdkVersion)) {
                         findings.push({
                            severity: "Informational",
                            description: "The `targetSdkVersion` attribute is missing or invalid.",
                            recommendation: "You should explicitly set `android:targetSdkVersion` to a modern API level to ensure your app benefits from the latest security and privacy features. The minimum recommended version is 29."
                        });
                    } else if (targetSdkVersion < minimumRecommendedVersion) {
                        findings.push({
                            severity: "Medium",
                            description: `The app targets an older SDK version (${targetSdkVersion}).`,
                            recommendation: `Updating your \`targetSdkVersion\` to at least ${minimumRecommendedVersion} (Android 10) is highly recommended. Older SDKs may not enforce modern security and privacy features, leaving your app vulnerable to issues like cleartext traffic, legacy permissions, and insecure storage defaults.`
                        });
                    }
                }
            }
        }

        if (applicationTag) {
            // --- Check for debuggable flag (if enabled) ---
            if (enableDebuggableCheck) {
                const debuggable = applicationTag.getAttribute("android:debuggable");
                if (debuggable === "true") {
                    findings.push({
                        severity: "High",
                        description: "Application is debuggable.",
                        recommendation: "Set `android:debuggable=\"false\"` in your `AndroidManifest.xml` for production builds. This prevents attackers from attaching debuggers, inspecting runtime data, or executing arbitrary code."
                    });
                }
            }

            // --- Check for allowBackup flag (if enabled) ---
            if (enableAllowBackupCheck) {
                const allowBackup = applicationTag.getAttribute("android:allowBackup");
                if (allowBackup === "true" || allowBackup === null) { // null means default true for API < 23
                    findings.push({
                        severity: "Medium",
                        description: "Application allows backup of data.",
                        recommendation: "Set `android:allowBackup=\"false\"` in your `AndroidManifest.xml` if your app handles sensitive data. This prevents users (or attackers with adb access) from backing up and restoring your app's private data, which might contain sensitive information."
                    });
                }
            }
            
            // --- Check for `android:fullBackupContent` (if enabled) ---
            if (enableFullBackupContentCheck) {
                const allowBackup = applicationTag.getAttribute("android:allowBackup");
                const fullBackupContent = applicationTag.getAttribute("android:fullBackupContent");

                // Check if allowBackup is true (or default) and fullBackupContent is not configured securely.
                if ((allowBackup === "true" || allowBackup === null) && fullBackupContent !== "@xml/data_exclusion_rules") {
                    findings.push({
                        severity: "Medium",
                        description: `The application allows backup and does not seem to have a secure \`android:fullBackupContent\` configuration.`,
                        recommendation: "Even with `allowBackup='true'`, you should define a custom `fullBackupContent` XML file to specify exactly what data should be included in the backup, and explicitly exclude sensitive information. If you don't configure this, all of your app's data could be backed up. Alternatively, set `android:allowBackup='false'` if no backup is needed."
                    });
                }
            }

            // --- Check for cleartext traffic and Network Security Configuration (if enabled) ---
            if (enableCleartextCheck) {
                const usesCleartextTraffic = applicationTag.getAttribute("android:usesCleartextTraffic");
                const networkSecurityConfig = applicationTag.getAttribute("android:networkSecurityConfig");

                if (usesCleartextTraffic === "true") {
                    findings.push({
                        severity: "High",
                        description: "Application explicitly allows cleartext HTTP traffic (`android:usesCleartextTraffic=\"true\"`).",
                        recommendation: "Set `android:usesCleartextTraffic=\"false\"` and implement a Network Security Configuration (NSC) to enforce HTTPS. Cleartext traffic is highly vulnerable to eavesdropping and tampering (Man-in-the-Middle attacks)."
                    });
                } else if (!networkSecurityConfig && usesCleartextTraffic !== "false") {
                    // This condition flags if no NSC is present AND cleartext is not explicitly disallowed.
                    // On Android P (API 28) and above, cleartext traffic is blocked by default,
                    // but explicitly setting NSC is still best practice for fine-grained control.
                    findings.push({
                        severity: "Medium",
                        description: "No Network Security Configuration (NSC) found or cleartext traffic not explicitly disallowed. This may allow cleartext HTTP traffic on older Android versions or if default behavior is overridden.",
                        recommendation: "Implement a robust Network Security Configuration (NSC) XML file and reference it with `android:networkSecurityConfig` in your `AndroidManifest.xml` to enforce secure network communication (HTTPS) and prevent cleartext traffic. For Android P+ (API 28+), cleartext is blocked by default, but NSC offers more control."
                    });
                }
            }
            
            // --- Check for hardcoded secrets in meta-data (if enabled) ---
            if (enableHardcodedSecretCheck) {
                const metaDataTags = xmlDoc.getElementsByTagName("meta-data");
                Array.from(metaDataTags).forEach(metaTag => {
                    const name = metaTag.getAttribute("android:name")?.toLowerCase();
                    const value = metaTag.getAttribute("android:value");
                    // Check for common keywords in the attribute name
                    if (name && value && (name.includes("key") || name.includes("secret") || name.includes("token") || name.includes("password"))) {
                        findings.push({
                            severity: "High",
                            description: `Potentially hardcoded secret found in a \`<meta-data>\` tag: \`${name}\`.`,
                            recommendation: "Avoid storing sensitive data like API keys, secrets, or tokens directly in the `AndroidManifest.xml`. An attacker can easily decompile the app and extract this information. Store secrets securely, for example, by fetching them from a secure server at runtime or using a dedicated secrets management library."
                        });
                    }
                });
            }

            // --- Check for `android:testOnly` flag (if enabled) ---
            if (enableTestOnlyCheck) {
                const testOnly = applicationTag.getAttribute("android:testOnly");
                if (testOnly === "true") {
                    findings.push({
                        severity: "High",
                        description: `The application tag has the \`android:testOnly="true"\` attribute set.`,
                        recommendation: "The `testOnly` flag indicates the APK is for testing purposes only. It should never be released to production as it can expose features and APIs that are not intended for general use. Ensure this flag is removed before building your release APK."
                    });
                }
            }
            
            // --- Check for `android:backupAgent` (if enabled) ---
            if (enableBackupAgentCheck) {
                const backupAgent = applicationTag.getAttribute("android:backupAgent");
                if (backupAgent) {
                     findings.push({
                        severity: "Informational",
                        description: `A custom backup agent is defined: \`${backupAgent}\`.`,
                        recommendation: "Custom backup agents should be carefully audited to ensure they handle sensitive data securely and do not expose it during the backup process. Consider the MASTG recommendations for secure data handling in backups."
                    });
                }
            }
            
            // --- Check for `android:allowClearUserData` (if enabled) ---
            if (enableAllowClearUserDataCheck) {
                const allowClearUserData = applicationTag.getAttribute("android:allowClearUserData");
                if (allowClearUserData === "true") {
                    findings.push({
                        severity: "Low",
                        description: `The \`android:allowClearUserData="true"\` attribute is set on the application tag.`,
                        recommendation: "This attribute allows users to clear your app's data from the system settings. While this is often a desired feature, ensure that any data stored is not critical for the app's security model, as an attacker could potentially leverage this to reset state or bypass certain controls. If you handle sensitive data, this can be a relevant finding."
                    });
                }
            }

            // --- Check for `android:extractNativeLibs` (if enabled) ---
            if (enableExtractNativeLibsCheck) {
                const extractNativeLibs = applicationTag.getAttribute("android:extractNativeLibs");
                if (extractNativeLibs === "false") {
                    findings.push({
                        severity: "Low",
                        description: `The application has \`android:extractNativeLibs="false"\`.`,
                        recommendation: "This setting can save space by not extracting native libraries to the file system. However, it can make it harder for some debugging and security analysis tools to work with the app. For production, ensure this configuration doesn't hinder your ability to diagnose issues or perform necessary checks."
                    });
                }
            }

            // --- Check for sensitive process names (if enabled) ---
            if (enableSensitiveProcessNameCheck) {
                const processName = applicationTag.getAttribute("android:process");
                if (processName) {
                    const sensitiveKeywords = ["root", "system", "su", "privileged", "admin", "core", "data"];
                    if (sensitiveKeywords.some(keyword => processName.toLowerCase().includes(keyword))) {
                         findings.push({
                            severity: "Informational",
                            description: `The application process name \`${processName}\` contains a sensitive keyword.`,
                            recommendation: "While an app cannot elevate its privileges by simply using a sensitive process name, this could be a sign of a developer's misunderstanding of the Android security model or an attempt to mislead analysts. Ensure your process names are benign and not misleading."
                        });
                    }
                }
            }

            // NEW: Check for hardware acceleration being disabled
            if (enableHardwareAcceleratedCheck) {
                const hardwareAccelerated = applicationTag.getAttribute("android:hardwareAccelerated");
                if (hardwareAccelerated === "false") {
                    findings.push({
                        severity: "Informational",
                        description: `The application has \`android:hardwareAccelerated="false"\`.`,
                        recommendation: "While not a direct security issue, disabling hardware acceleration can indicate that the app is using older UI frameworks that may have other vulnerabilities. It's generally recommended to keep hardware acceleration enabled unless there's a specific compatibility reason to disable it."
                    });
                }
            }
            
             // NEW: Check for fullscreen themes
            if (enableFullscreenThemeCheck) {
                const theme = applicationTag.getAttribute("android:theme");
                const activities = xmlDoc.getElementsByTagName("activity");

                // Check application theme
                if (theme && theme.includes("NoTitleBar") || theme && theme.includes("Fullscreen")) {
                     findings.push({
                        severity: "Low",
                        description: `The application uses a theme that hides the status bar or title bar.`,
                        recommendation: "The use of `NoTitleBar` or `Fullscreen` themes can hide critical information from the user. While often used for games, it can also be used in phishing or overlay attacks. Ensure this is intentional and not part of a malicious design."
                    });
                }
                
                // Check individual activity themes
                Array.from(activities).forEach(activity => {
                    const activityTheme = activity.getAttribute("android:theme");
                    if (activityTheme && (activityTheme.includes("NoTitleBar") || activityTheme.includes("Fullscreen"))) {
                        findings.push({
                            severity: "Low",
                            description: `Activity '${activity.getAttribute("android:name")}' uses a theme that hides the status bar or title bar.`,
                            recommendation: "Using `NoTitleBar` or `Fullscreen` themes can hide critical information from the user. Ensure this is intentional and not part of a malicious design that could be used for overlay attacks."
                        });
                    }
                });
            }
            
             // NEW: Check for uses-feature tags
            if (enableUsesFeatureCheck) {
                const usesFeatureTags = xmlDoc.getElementsByTagName("uses-feature");
                if (usesFeatureTags.length > 0) {
                    const features = Array.from(usesFeatureTags).map(tag => tag.getAttribute("android:name"));
                    findings.push({
                        severity: "Informational",
                        description: "The application declares hardware or software feature requirements.",
                        recommendation: `The app requires the following features: ${features.join(', ')}. This information is important for threat modeling and understanding the app's attack surface. Review this list to ensure the app doesn't require any unnecessary or sensitive features.`
                    });
                }
            }

        } else {
            findings.push({
                severity: "Error",
                description: "No `<application>` tag found in the manifest.",
                recommendation: "Ensure your AndroidManifest.xml is valid and contains an `<application>` tag."
            });
        }
        
        // --- Check for exported components without proper permissions (if enabled) ---
        if (enableExportedCheck) {
            const components = ["activity", "service", "receiver", "provider"];
            components.forEach(componentName => {
                const elements = xmlDoc.getElementsByTagName(componentName);
                Array.from(elements).forEach(el => {
                    const exported = el.getAttribute("android:exported");
                    const permission = el.getAttribute("android:permission");
                    const readPermission = el.getAttribute("android:readPermission"); // For providers
                    const writePermission = el.getAttribute("android:writePermission"); // For providers
                    const name = el.getAttribute("android:name");

                    if (exported === "true") {
                        if (!permission && componentName !== "provider") {
                            findings.push({
                                severity: "High",
                                description: `Exported ${componentName} '${name}' without a permission attribute.`,
                                recommendation: `Add a strong custom permission to the exported ${componentName} '${name}' (e.g., \`android:permission="com.yourpackage.permission.MY_CUSTOM_PERMISSION"\`) or set \`android:exported="false"\` if it's not intended for other apps. This prevents other apps from invoking your component without authorization.`
                            });
                        } else if (componentName === "provider" && (!readPermission && !writePermission && !permission)) {
                             findings.push({
                                severity: "High",
                                description: `Exported Content Provider '${name}' without readPermission, writePermission, or a general permission.`,
                                recommendation: `For exported Content Providers, always specify \`android:readPermission\` and/or \`android:writePermission\` (or a general \`android:permission\`) to control access to your data. Alternatively, set \`android:exported="false"\` if it's not meant for external access.`
                            });
                        } else {
                            // If exported="true" but has a permission, it's informational/low severity
                            // as the permission might still be weak or commonly granted.
                            let permDetails = permission ? `with permission '${permission}'` : '';
                            if (componentName === "provider") {
                                if (readPermission) permDetails += ` readPermission='${readPermission}'`;
                                if (writePermission) permDetails += ` writePermission='${writePermission}'`;
                            }
                            findings.push({
                                severity: "Low",
                                description: `Exported ${componentName} '${name}' ${permDetails.trim()}.`,
                                recommendation: `Ensure the specified permission(s) are adequately protected and not overly broad. Consider setting \`android:exported="false"\` if this component is only for internal app use.`
                            });
                        }
                    }
                });
            });
        }
        
        // --- Check for `android:exported` on components with intent filters, as the default changes based on API level
        // This check complements the existing `enableImplicitIntentCheck`
        const componentsWithIntentFilters = ["activity", "service", "receiver"];
        componentsWithIntentFilters.forEach(componentName => {
            const elements = xmlDoc.getElementsByTagName(componentName);
            Array.from(elements).forEach(el => {
                const intentFilters = el.getElementsByTagName("intent-filter");
                const exported = el.getAttribute("android:exported");
                const name = el.getAttribute("android:name");

                // If component has an intent filter but no explicit `exported` attribute.
                if (intentFilters.length > 0 && exported === null) {
                    findings.push({
                        severity: "Medium",
                        description: `Component '${name}' has an intent filter but no explicit \`android:exported\` attribute.`,
                        recommendation: "The default value of `android:exported` for components with an intent filter is `true` for `targetSdkVersion` 30 and below, and `false` for 31 and above. To avoid unintended security issues due to version compatibility, always explicitly set `android:exported` to `true` or `false`."
                    });
                }
            });
        });

        // --- Check for deep link activities (if enabled) ---
        if (enableDeepLinkCheck) {
            const activities = xmlDoc.getElementsByTagName("activity");
            Array.from(activities).forEach(activity => {
                const intentFilters = activity.getElementsByTagName("intent-filter");
                Array.from(intentFilters).forEach(filter => {
                    const dataTags = filter.getElementsByTagName("data");
                    if (dataTags.length > 0) {
                        const name = activity.getAttribute("android:name");
                         findings.push({
                            severity: "Medium",
                            description: `Activity '${name}' handles deep links.`,
                            recommendation: `Always validate and sanitize all data received from deep links. An attacker can use deep links to send malicious input to your app, leading to vulnerabilities like authorization bypass or sensitive data exposure. For example, ensure the URL comes from a trusted host.`
                        });
                    }
                });
            });
        }
        
        // --- Check for insecure deep link schemes (if enabled) ---
        if (enableInsecureDeepLinkSchemeCheck) {
            const activities = xmlDoc.getElementsByTagName("activity");
            Array.from(activities).forEach(activity => {
                const exported = activity.getAttribute("android:exported");
                const intentFilters = activity.getElementsByTagName("intent-filter");
                if (exported === "true") {
                    Array.from(intentFilters).forEach(filter => {
                        const dataTags = filter.getElementsByTagName("data");
                        Array.from(dataTags).forEach(data => {
                            const scheme = data.getAttribute("android:scheme");
                            if (scheme === "http") {
                                const name = activity.getAttribute("android:name");
                                findings.push({
                                    severity: "High",
                                    description: `Exported activity '${name}' handles deep links with an insecure \`http\` scheme.`,
                                    recommendation: "Using `http` for deep links can expose sensitive data or parameters to eavesdropping. Always use `https` for deep links to ensure the communication is encrypted and secure against man-in-the-middle attacks."
                                });
                            }
                        });
                    });
                }
            });
        }

        // --- Check for implicitly exposed components (if enabled) ---
        if (enableImplicitIntentCheck) {
            const components = ["activity", "service", "receiver"]; // Providers are a bit different, handled by exported check
            components.forEach(componentName => {
                const elements = xmlDoc.getElementsByTagName(componentName);
                Array.from(elements).forEach(el => {
                    const exported = el.getAttribute("android:exported");
                    const intentFilters = el.getElementsByTagName("intent-filter");
                    const name = el.getAttribute("android:name");
                    // Flag components with intent filters that don't explicitly set exported="false"
                    // On newer Android versions, exported is false by default if an intent filter exists,
                    // but it's still best practice to explicitly set it to avoid issues on older platforms.
                    if (intentFilters.length > 0 && exported !== "false") {
                         findings.push({
                            severity: "Medium",
                            description: `Component '${name}' has an intent filter but does not explicitly set \`android:exported="false"\`.`,
                            recommendation: "Components with intent filters can be invoked by other apps. To prevent unintentional exposure and potential hijacking, explicitly set `android:exported=\"false\"` unless the component is specifically designed for inter-app communication."
                        });
                    }
                });
            });
        }
        
        // --- Check for components running in a separate process (if enabled) ---
        if (enableSeparateProcessCheck) {
            const components = ["activity", "service", "receiver", "provider"];
            components.forEach(componentName => {
                const elements = xmlDoc.getElementsByTagName(componentName);
                Array.from(elements).forEach(el => {
                    const processName = el.getAttribute("android:process");
                    const name = el.getAttribute("android:name");
                    if (processName) {
                        findings.push({
                            severity: "Informational",
                            description: `Component '${name}' is configured to run in a separate process named \`${processName}\`.`,
                            recommendation: "Running components in separate processes can have benefits but introduces a new security surface area for inter-process communication (IPC). Ensure all IPC mechanisms are secure and that the component's permissions are correctly configured to prevent unauthorized access."
                        });
                    }
                });
            });
        }

        // --- Check for taskAffinity misconfiguration (if enabled) ---
        if (enableTaskAffinityCheck) {
            const activities = xmlDoc.getElementsByTagName("activity");
            Array.from(activities).forEach(activity => {
                const taskAffinity = activity.getAttribute("android:taskAffinity");
                const exported = activity.getAttribute("android:exported");
                const name = activity.getAttribute("android:name");
                // Flag an exported activity that has taskAffinity defined, which is a known vector for task hijacking
                if (exported === "true" && taskAffinity) {
                    findings.push({
                        severity: "High",
                        description: `Exported activity '${name}' has a custom \`android:taskAffinity\` of \`${taskAffinity}\`.`,
                        recommendation: "An exported activity with a custom task affinity can be a security risk, as a malicious application could manipulate the task stack to confuse the user or steal data. Consider if this is truly necessary, and if so, implement robust checks to ensure the calling activity is trusted."
                    });
                }
            });
        }
        
        // --- Check for `android:allowTaskReparenting` (if enabled) ---
        if (enableAllowTaskReparentingCheck) {
            const activities = xmlDoc.getElementsByTagName("activity");
            Array.from(activities).forEach(activity => {
                const allowReparenting = activity.getAttribute("android:allowTaskReparenting");
                const name = activity.getAttribute("android:name");
                if (allowReparenting === "true") {
                    findings.push({
                        severity: "Medium",
                        description: `Activity '${name}' allows task reparenting.`,
                        recommendation: "When `allowTaskReparenting` is set to `true`, an activity can be moved from the task of the application that started it to the task of the application it has an affinity for. This can lead to unexpected behavior and could be exploited for task hijacking. Use this attribute with caution."
                    });
                }
            });
        }

        // --- Check for custom permissions with weak protection levels (if enabled) ---
        if (enableCustomPermissionCheck) {
            const permissionTags = xmlDoc.getElementsByTagName("permission");
            Array.from(permissionTags).forEach(permTag => {
                const protectionLevel = permTag.getAttribute("android:protectionLevel");
                const name = permTag.getAttribute("android:name");
                if (protectionLevel === "normal") {
                    findings.push({
                        severity: "High",
                        description: `Custom permission '${name}' has a weak protection level: \`normal\`.`,
                        recommendation: "A 'normal' protection level permission is granted automatically to any app requesting it, offering no security. For permissions that protect sensitive data or functionality, use a stronger protection level like `signature` or `signatureOrSystem` to ensure only apps signed with the same certificate can acquire them."
                    });
                }
            });
        }
        
        // NEW: Check for `dangerous` protection level on custom permissions
        if (enableProtectionLevelDangerousCheck) {
            const permissionTags = xmlDoc.getElementsByTagName("permission");
            Array.from(permissionTags).forEach(permTag => {
                const protectionLevel = permTag.getAttribute("android:protectionLevel");
                const name = permTag.getAttribute("android:name");
                if (protectionLevel === "dangerous") {
                    findings.push({
                        severity: "High",
                        description: `Custom permission '${name}' has a protection level of \`dangerous\`.`,
                        recommendation: "A `dangerous` protection level means the user will be prompted to grant this permission, similar to system-defined dangerous permissions. However, it's generally recommended to avoid defining custom permissions with this level unless your app is a system-level component, as it can confuse users and lead to over-permissioning."
                    });
                }
            });
        }
        
        // NEW: Check for `grantUriPermissions` on Content Providers
        if (enableGrantUriPermissionsCheck) {
            const providerTags = xmlDoc.getElementsByTagName("provider");
            Array.from(providerTags).forEach(providerTag => {
                const grantUriPermissions = providerTag.getAttribute("android:grantUriPermissions");
                const name = providerTag.getAttribute("android:name");
                if (grantUriPermissions === "true") {
                    findings.push({
                        severity: "Medium",
                        description: `Content provider '${name}' has \`android:grantUriPermissions="true"\`.`,
                        recommendation: "While sometimes necessary for sharing specific data with other apps, `grantUriPermissions` should be used with extreme caution. It can temporarily grant access to a URI's data without permanent permissions. Ensure that the URIs being granted are limited and that the code handling these URIs is not vulnerable to path traversal attacks."
                    });
                }
            });
        }

        // --- Check for sensitive permissions (if enabled) ---
        if (enablePermissionCheck) {
            const permissions = xmlDoc.getElementsByTagName("uses-permission");
            Array.from(permissions).forEach(perm => {
                const name = perm.getAttribute("android:name");
                if (name) {
                    let severity = "Informational";
                    let recommendation = `The app requests permission: ${name}. Review if this permission is strictly necessary for your app's functionality. Only request permissions essential for your app's core features.`;

                    if (name.includes("EXTERNAL_STORAGE") || name.includes("CAMERA") || name.includes("LOCATION") || name.includes("CONTACTS") || name.includes("CALL_LOG") || name.includes("READ_SMS") || name.includes("SEND_SMS")) {
                        severity = "Medium";
                        recommendation = `The app requests sensitive permission: ${name}. Ensure this permission is absolutely necessary and that data accessed through it is handled securely and with user consent. Avoid storing sensitive data on external storage without encryption.`;
                    } else if (name.includes("SYSTEM_ALERT_WINDOW") || name.includes("WRITE_SETTINGS") || name.includes("BIND_DEVICE_ADMIN") || name.includes("INSTALL_PACKAGES")) {
                        severity = "High";
                        recommendation = `The app requests a highly sensitive or dangerous permission: ${name}. These permissions can be abused for malicious purposes (e.g., overlay attacks, device control). Only request if absolutely critical and implement robust security checks around their usage. Clearly explain to the user why this permission is needed.`;
                    }

                    findings.push({
                        severity,
                        description: `App requests permission: ${name}.`,
                        recommendation
                    });
                }
            });
        }
        
        // --- Check for optional libraries (`required="false"`) (if enabled) ---
        if (enableOptionalLibraryCheck) {
            const usesLibraryTags = xmlDoc.getElementsByTagName("uses-library");
            Array.from(usesLibraryTags).forEach(libTag => {
                const required = libTag.getAttribute("android:required");
                const name = libTag.getAttribute("android:name");
                if (required === "false") {
                     findings.push({
                        severity: "Low",
                        description: `The app uses the optional library \`${name}\`.`,
                        recommendation: "Declaring a library as `required='false'` means your app will still install and run if the library isn't available. Ensure that the absence of this library does not create a security vulnerability or cause unexpected behavior in features that rely on it, especially if it provides critical security functionality."
                    });
                }
            });
        }

        return findings;
    };

    // Function to toggle between light and dark modes
    const toggleDarkMode = () => {
        setDarkMode(prevMode => !prevMode);
    };

    // Function to toggle the analysis options section
    const toggleOptionsExpanded = () => {
        setIsOptionsExpanded(prev => !prev);
    };

    // Function to download analysis results
    const downloadResults = () => {
        if (analysisResults.length === 0) {
            setError("No analysis results to download.");
            return;
        }

        let reportContent = "Android Manifest SAST Analysis Report\n\n";
        reportContent += "=========================================\n\n";

        analysisResults.forEach((finding, index) => {
            reportContent += `Finding ${index + 1}:\n`;
            reportContent += `  Severity: ${finding.severity}\n`;
            reportContent += `  Description: ${finding.description}\n`;
            reportContent += `  Recommendation: ${finding.recommendation}\n`;
            reportContent += "-----------------------------------------\n\n";
        });

        const blob = new Blob([reportContent], { type: 'text/plain;charset=utf-8' });
        const url = URL.createObjectURL(blob);
        const link = document.createElement('a');
        link.href = url;
        link.download = 'sast_report.txt';
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
        URL.revokeObjectURL(url); // Clean up the object URL
    };

    // Helper component for the toggle/checkbox
    const ToggleSwitch = ({ label, checked, onChange }) => (
        <label className="flex items-center space-x-3 cursor-pointer">
            <div className={`relative inline-block w-12 h-6 rounded-full transition-colors duration-200 ease-in-out ${checked ? toggleBgChecked : toggleBgUnchecked} focus:outline-none focus:ring-2 focus:ring-teal-500`}>
                <input type="checkbox" checked={checked} onChange={onChange} className="sr-only" />
                <span className={`inline-block w-6 h-6 transform bg-white rounded-full shadow-md transition-transform duration-200 ease-in-out ${checked ? 'translate-x-6 bg-teal-500' : 'translate-x-0'}`}></span>
            </div>
            <span className={`text-base font-medium ${checked ? 'text-gray-800 dark:text-gray-200' : 'text-gray-500 dark:text-gray-400'}`}>
                {label}
            </span>
        </label>
    );

    return (
        <div className={`min-h-screen p-4 sm:p-8 font-sans flex flex-col items-center ${mainBackground} transition-colors duration-500`}>
            <script src="https://cdn.tailwindcss.com"></script>
            <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700&display=swap" rel="stylesheet" />

            <style>
                {`
                body {
                    font-family: 'Inter', sans-serif;
                }
                .gradient-button {
                    transition: 0.5s;
                    background-size: 200% auto;
                    color: white;
                    box-shadow: 0 4px 15px rgba(0, 0, 0, 0.2);
                }
                .gradient-button:hover {
                    background-position: right center;
                }
                .card {
                    box-shadow: 0 10px 25px rgba(0, 0, 0, 0.1);
                }
                .dark .card {
                    box-shadow: 0 10px 25px rgba(0, 0, 0, 0.3);
                }
                /* Dark mode specific styles for textarea/input */
                .dark textarea, .dark input[type="file"] {
                    border-color: #4b5563;
                    color: #d1d5db;
                }
                .dark textarea::placeholder {
                    color: #9ca3af;
                }

                /* --- Severity Colors (Colorblind-Friendly) --- */
                .severity-high { background-color: #fee2e2; color: #b91c1c; border-left: 4px solid #dc2626; }
                .dark .severity-high { background-color: #450a0a; color: #fca5a5; border-left: 4px solid #ef4444; }
                .severity-medium { background-color: #fff7ed; color: #c2410c; border-left: 4px solid #ea580c; }
                .dark .severity-medium { background-color: #7c2d12; color: #fdba74; border-left: 4px solid #f97316; }
                .severity-low { background-color: #eff6ff; color: #1d4ed8; border-left: 4px solid #2563eb; }
                .dark .severity-low { background-color: #1e3a8a; color: #93c5fd; border-left: 4px solid #3b82f6; }
                .severity-informational { background-color: #ecfeff; color: #0891b2; border-left: 4px solid #06b6d4; }
                .dark .severity-informational { background-color: #042f2e; color: #67e8f9; border-left: 4px solid #22d3ee; }
                .severity-error { background-color: #fee2e2; color: #b91c1c; border-left: 4px solid #dc2626; }
                .dark .severity-error { background-color: #450a0a; color: #fca5a5; border-left: 4px solid #ef4444; }

                /* --- Black-Teal Theme --- */
                .gradient-button { background-image: linear-gradient(to right, #14B8A6 0%, #22D3EE 51%, #14B8A6 100%); }
                .dark .card, .dark .options-card { background-color: #1a202c; }
                .dark textarea { background-color: #2d3748; }
                .file-button { background-color: #e0f2f1; color: #0f766e; }
                .dark .file-button { background-color: #0d9488; color: white; }
                `}
            </style>

            <header className="w-full max-w-4xl text-center mb-8 relative">
                <h1 className={`text-4xl sm:text-5xl font-extrabold ${headerTextColor} mb-4`}>
                    Android SAST Simulator
                </h1>
                <p className="text-lg text-gray-600 dark:text-gray-300">
                    Analyze your `AndroidManifest.xml` for common security misconfigurations.
                </p>
                <p className="text-sm text-gray-500 dark:text-gray-400 mt-2">
                    <strong className="text-red-500 dark:text-red-300">Note:</strong> This is a simplified client-side simulation, not a full-fledged SAST tool. It focuses on `AndroidManifest.xml` analysis.
                </p>

                {/* Dark Mode Controls */}
                <div className="absolute top-0 right-0 flex items-center space-x-2">
                    <button
                        onClick={toggleDarkMode}
                        className="p-2 rounded-full bg-gray-200 dark:bg-gray-700 text-gray-800 dark:text-gray-200 shadow-md hover:scale-105 transition-transform duration-200"
                        title={darkMode ? 'Switch to Light Mode' : 'Switch to Dark Mode'}
                    >
                        {darkMode ? (
                            <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M20.354 15.354A9 9 0 018.646 3.646 9.003 9.003 0 0012 21a9 9 0 008.354-5.646z"></path>
                            </svg>
                        ) : (
                            <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M12 3v1m0 16v1m9-9h1M4 12H3m15.325 6.675l-.707-.707M6.343 6.343l-.707-.707m12.728 0l-.707.707M6.343 17.657l-.707.707M16 12a4 4 0 11-8 0 4 4 0 018 0z"></path>
                            </svg>
                        )}
                    </button>
                </div>
            </header>

            <main className={`w-full max-w-4xl rounded-xl p-6 sm:p-8 transition-colors duration-500 ${cardBackground} ${darkMode ? 'dark' : ''}`}>
                {showInstructions && (
                    <div className={`mb-6 p-4 rounded-lg ${instructionsBg}`}>
                        <h2 className="text-xl font-semibold mb-2">How to Use:</h2>
                        <ol className="list-decimal list-inside space-y-2">
                            <li>
                                **Upload your APK file** below. This step is primarily for context.
                            </li>
                            <li>
                                **Extract your `AndroidManifest.xml` content:**
                                <ul className="list-disc list-inside ml-4 mt-1 text-sm">
                                    <li>If you have your app's source code, locate `app/src/main/AndroidManifest.xml`.</li>
                                    <li>
                                        If you only have an APK, you can use a tool like <code className="bg-gray-200 dark:bg-gray-600 px-1 rounded">apktool</code> to decompile it:
                                        <pre className="bg-gray-100 dark:bg-gray-800 p-2 rounded text-xs mt-1 overflow-x-auto">
                                            apktool d your-app.apk -o decompiled-app<br/>
                                            cd decompiled-app<br/>
                                            cat AndroidManifest.xml
                                        </pre>
                                        Then copy the entire content.
                                    </li>
                                </ul>
                            </li>
                            <li>
                                **Paste the copied XML content** into the text area below.
                            </li>
                            <li>
                                Click "Analyze Manifest" to see potential security findings.
                            </li>
                        </ol>
                    </div>
                )}

                <div className="mb-6">
                    <label htmlFor="apk-upload" className="block text-lg font-medium text-gray-700 dark:text-gray-300 mb-2">
                        1. Upload Android APK (Optional, for context):
                    </label>
                    <input
                        type="file"
                        id="apk-upload"
                        accept=".apk"
                        onChange={handleFileChange}
                        className={`block w-full text-sm text-gray-500 dark:text-gray-400
                                   file:mr-4 file:py-2 file:px-4
                                   file:rounded-full file:border-0
                                   file:text-sm file:font-semibold
                                   ${fileButtonClass}
                                   `}
                    />
                    {apkFile && (
                        <p className="mt-2 text-sm text-gray-600 dark:text-gray-400">Selected file: <span className="font-semibold">{apkFile.name}</span></p>
                    )}
                </div>

                <div className="mb-6">
                    <label htmlFor="manifest-input" className="block text-lg font-medium text-gray-700 dark:text-gray-300 mb-2">
                        2. Paste your `AndroidManifest.xml` content here:
                    </label>
                    <textarea
                        id="manifest-input"
                        className={`w-full h-64 p-4 border rounded-lg focus:ring-teal-500 focus:border-teal-500 font-mono text-sm resize-y
                        ${darkMode ? 'dark bg-gray-700 text-gray-100' : 'bg-gray-100 text-gray-800'}
                        `}
                        placeholder={`<?xml version="1.0" encoding="utf-8"?>\n<manifest xmlns:android="http://schemas.android.com/apk/res/android" ...>\n    <application ...>\n        ...\n    </application>\n</manifest>`}
                        value={manifestContent}
                        onChange={handleManifestChange}
                    ></textarea>
                </div>

                {/* Analysis Options Section with Collapsible Feature */}
                <div className={`mb-6 p-4 rounded-lg options-card ${optionsBg}`}>
                    <button
                        onClick={toggleOptionsExpanded}
                        className="flex justify-between items-center w-full focus:outline-none"
                    >
                        <h3 className="text-xl font-bold text-gray-700 dark:text-gray-300">Analysis Options</h3>
                        <svg
                            className={`w-6 h-6 transform transition-transform duration-300 ${isOptionsExpanded ? 'rotate-180' : 'rotate-0'}`}
                            fill="none"
                            stroke="currentColor"
                            viewBox="0 0 24 24"
                            xmlns="http://www.w3.org/2000/svg"
                        >
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M19 9l-7 7-7-7"></path>
                        </svg>
                    </button>
                    
                    {/* The collapsible content */}
                    <div className={`transition-all duration-500 ease-in-out overflow-hidden ${isOptionsExpanded ? 'max-h-full opacity-100 mt-4' : 'max-h-0 opacity-0'}`}>
                        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                            <ToggleSwitch
                                label="Check for `android:debuggable`"
                                checked={enableDebuggableCheck}
                                onChange={(e) => setEnableDebuggableCheck(e.target.checked)}
                            />
                            <ToggleSwitch
                                label="Check for `android:allowBackup`"
                                checked={enableAllowBackupCheck}
                                onChange={(e) => setEnableAllowBackupCheck(e.target.checked)}
                            />
                            <ToggleSwitch
                                label="Check for cleartext traffic and NSC"
                                checked={enableCleartextCheck}
                                onChange={(e) => setEnableCleartextCheck(e.target.checked)}
                            />
                            <ToggleSwitch
                                label="Check for exported components"
                                checked={enableExportedCheck}
                                onChange={(e) => setEnableExportedCheck(e.target.checked)}
                            />
                            <ToggleSwitch
                                label="Check for sensitive permissions"
                                checked={enablePermissionCheck}
                                onChange={(e) => setEnablePermissionCheck(e.target.checked)}
                            />
                            <ToggleSwitch
                                label="Check for insecure `targetSdkVersion`"
                                checked={enableTargetSdkVersionCheck}
                                onChange={(e) => setEnableTargetSdkVersionCheck(e.target.checked)}
                            />
                            <ToggleSwitch
                                label="Check for hardcoded secrets"
                                checked={enableHardcodedSecretCheck}
                                onChange={(e) => setEnableHardcodedSecretCheck(e.target.checked)}
                            />
                            <ToggleSwitch
                                label="Check for deep links"
                                checked={enableDeepLinkCheck}
                                onChange={(e) => setEnableDeepLinkCheck(e.target.checked)}
                            />
                             <ToggleSwitch
                                label="Check for `sharedUserId`"
                                checked={enableSharedUserIdCheck}
                                onChange={(e) => setEnableSharedUserIdCheck(e.target.checked)}
                            />
                            <ToggleSwitch
                                label="Check for implicit intent exposure"
                                checked={enableImplicitIntentCheck}
                                onChange={(e) => setEnableImplicitIntentCheck(e.target.checked)}
                            />
                            <ToggleSwitch
                                label="Check for separate process"
                                checked={enableSeparateProcessCheck}
                                onChange={(e) => setEnableSeparateProcessCheck(e.target.checked)}
                            />
                            <ToggleSwitch
                                label="Check for insecure `minSdkVersion`"
                                checked={enableMinSdkVersionCheck}
                                onChange={(e) => setEnableMinSdkVersionCheck(e.target.checked)}
                            />
                            <ToggleSwitch
                                label="Check for weak custom permissions"
                                checked={enableCustomPermissionCheck}
                                onChange={(e) => setEnableCustomPermissionCheck(e.target.checked)}
                            />
                            <ToggleSwitch
                                label="Check for `android:testOnly` flag"
                                checked={enableTestOnlyCheck}
                                onChange={(e) => setEnableTestOnlyCheck(e.target.checked)}
                            />
                            <ToggleSwitch
                                label="Check for insecure full backup content"
                                checked={enableFullBackupContentCheck}
                                onChange={(e) => setEnableFullBackupContentCheck(e.target.checked)}
                            />
                            <ToggleSwitch
                                label="Check for exported task affinity"
                                checked={enableTaskAffinityCheck}
                                onChange={(e) => setEnableTaskAffinityCheck(e.target.checked)}
                            />
                            <ToggleSwitch
                                label="Check for insecure deep link schemes"
                                checked={enableInsecureDeepLinkSchemeCheck}
                                onChange={(e) => setEnableInsecureDeepLinkSchemeCheck(e.target.checked)}
                            />
                            <ToggleSwitch
                                label="Check for custom backup agent"
                                checked={enableBackupAgentCheck}
                                onChange={(e) => setEnableBackupAgentCheck(e.target.checked)}
                            />
                            <ToggleSwitch
                                label="Check for task reparenting"
                                checked={enableAllowTaskReparentingCheck}
                                onChange={(e) => setEnableAllowTaskReparentingCheck(e.target.checked)}
                            />
                             <ToggleSwitch
                                label="Check for allow clear user data"
                                checked={enableAllowClearUserDataCheck}
                                onChange={(e) => setEnableAllowClearUserDataCheck(e.target.checked)}
                            />
                             <ToggleSwitch
                                label="Check for sensitive process names"
                                checked={enableSensitiveProcessNameCheck}
                                onChange={(e) => setEnableSensitiveProcessNameCheck(e.target.checked)}
                            />
                             <ToggleSwitch
                                label="Check for `extractNativeLibs`"
                                checked={enableExtractNativeLibsCheck}
                                onChange={(e) => setEnableExtractNativeLibsCheck(e.target.checked)}
                            />
                             <ToggleSwitch
                                label="Check for optional libraries"
                                checked={enableOptionalLibraryCheck}
                                onChange={(e) => setEnableOptionalLibraryCheck(e.target.checked)}
                            />
                            <ToggleSwitch
                                label="Check for 'dangerous' permissions"
                                checked={enableProtectionLevelDangerousCheck}
                                onChange={(e) => setEnableProtectionLevelDangerousCheck(e.target.checked)}
                            />
                             <ToggleSwitch
                                label="Check for disabled hardware acceleration"
                                checked={enableHardwareAcceleratedCheck}
                                onChange={(e) => setEnableHardwareAcceleratedCheck(e.target.checked)}
                            />
                             <ToggleSwitch
                                label="Check for fullscreen themes"
                                checked={enableFullscreenThemeCheck}
                                onChange={(e) => setEnableFullscreenThemeCheck(e.target.checked)}
                            />
                             <ToggleSwitch
                                label="Check for uses-feature tags"
                                checked={enableUsesFeatureCheck}
                                onChange={(e) => setEnableUsesFeatureCheck(e.target.checked)}
                            />
                            <ToggleSwitch
                                label="Check for `grantUriPermissions`"
                                checked={enableGrantUriPermissionsCheck}
                                onChange={(e) => setEnableGrantUriPermissionsCheck(e.target.checked)}
                            />
                        </div>
                    </div>
                </div>

                <button
                    onClick={performAnalysis}
                    disabled={isLoading || !manifestContent.trim()}
                    className={`w-full py-3 px-6 rounded-lg text-lg font-semibold gradient-button disabled:opacity-50 disabled:cursor-not-allowed
                    bg-gradient-to-r ${buttonGradient}`}
                >
                    {isLoading ? 'Analyzing...' : 'Analyze Manifest'}
                </button>

                {error && (
                    <div className={`mt-6 p-4 rounded-lg ${errorBg}`}>
                        <p className="font-semibold">Error:</p>
                        <p>{error}</p>
                    </div>
                )}

                {analysisResults.length > 0 && (
                    <div className="mt-8">
                        <h2 className={`text-2xl font-bold ${headerTextColor} mb-4`}>Analysis Results:</h2>
                        <div className="space-y-4">
                            {analysisResults.map((finding, index) => (
                                <div
                                    key={index}
                                    className={`p-4 rounded-lg shadow-sm ${
                                        finding.severity === 'High' ? 'severity-high' :
                                        finding.severity === 'Medium' ? 'severity-medium' :
                                        finding.severity === 'Low' ? 'severity-low' :
                                        finding.severity === 'Informational' ? 'severity-informational' :
                                        'severity-error'
                                    }`}
                                >
                                    <h3 className="text-lg font-semibold mb-1">
                                        Severity: {finding.severity}
                                    </h3>
                                    <p className="font-medium">{finding.description}</p>
                                    <p className="text-sm mt-2">
                                        <span className="font-semibold">Recommendation:</span> {finding.recommendation}
                                    </p>
                                </div>
                            ))}
                        </div>
                        {/* Download Results Button */}
                        <button
                            onClick={downloadResults}
                            className={`mt-6 w-full py-3 px-6 rounded-lg text-lg font-semibold gradient-button
                            bg-gradient-to-r ${buttonGradient}`}
                        >
                            Download Results
                        </button>
                    </div>
                )}
            </main>
        </div>
    );
};

export default App;
