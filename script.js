class PasswordAnalyzer {
    constructor() {
        this.commonPasswords = new Set([
            '123456', 'password', '12345678', 'qwerty', '123456789',
            '12345', '1234', '111111', '1234567', 'dragon',
            '123123', 'baseball', 'abc123', 'football', 'monkey',
            'letmein', 'shadow', 'master', '666666', 'qwertyuiop',
            'şifre', 'parola', 'ahmet', 'mehmet', 'ayşe', 'fatma'
        ]);
        
        this.currentTheme = 'light';
        this.currentLanguage = 'tr';
        this.passwordHistory = [];
        this.charts = {};
        this.breachCache = new Map();
        this.passwordComparison = [];
        
        this.init();
    }

    init() {
        console.log("🚀 Şifre Analiz Aracı Başlatılıyor...");
        this.loadFromLocalStorage();
        this.setupEventListeners();
        this.updateAllTexts();
        
        setTimeout(() => {
            this.initCharts();
            this.analyzePassword('');
        }, 200);
    }

    setupEventListeners() {
        document.getElementById('passwordInput').addEventListener('input', (e) => {
            this.analyzePassword(e.target.value);
        });

        document.getElementById('toggleVisibility').addEventListener('click', () => {
            const input = document.getElementById('passwordInput');
            const btn = document.getElementById('toggleVisibility');
            const type = input.type === 'password' ? 'text' : 'password';
            input.type = type;
            btn.textContent = type === 'password' ? '👁️' : '🔒';
        });

        document.getElementById('generateBtn').addEventListener('click', () => {
            this.generateStrongPassword();
        });

        document.getElementById('copyBtn').addEventListener('click', () => {
            this.copyToClipboard();
        });

        document.getElementById('startSimulation').addEventListener('click', () => {
            this.startBruteforceSimulation();
        });

        document.getElementById('themeToggle').addEventListener('click', () => {
            this.toggleTheme();
        });

        document.getElementById('languageToggle').addEventListener('click', () => {
            this.toggleLanguage();
        });

        document.getElementById('exportPDF').addEventListener('click', () => {
            this.exportPDF();
        });

        document.getElementById('exportCSV').addEventListener('click', () => {
            this.exportCSV();
        });

        
        document.getElementById('addComparePassword').addEventListener('click', () => {
            this.addPasswordToComparison();
        });

        document.getElementById('clearComparison').addEventListener('click', () => {
            this.clearComparison();
        });

        // 🆕 Şifre kural motoru event listeners
        document.getElementById('generatePolicy').addEventListener('click', () => {
            this.generatePasswordRules();
        });

        document.getElementById('applyPolicy').addEventListener('click', () => {
            this.applyPasswordRules();
        });
    }

    async analyzePassword(password) {
        const strength = this.calculateStrength(password);
        const breachData = await this.checkPasswordBreaches(password);
        
        this.updateAllDisplays(strength, password, breachData);
        
        if (password && password.length > 0) {
            this.addToHistory(password, strength);
        }
    }

    calculateStrength(password) {
        let score = 0;
        const analysis = {};

        analysis.length = password.length >= 8;
        score += password.length * 4;
        if (password.length >= 12) score += 10;

        analysis.hasUpper = /[A-Z]/.test(password);
        analysis.hasLower = /[a-z]/.test(password);
        if (analysis.hasUpper && analysis.hasLower) score += 10;

        analysis.hasNumber = /\d/.test(password);
        if (analysis.hasNumber) score += 10;

        analysis.hasSpecial = /[!@#$%^&*(),.?":{}|<>]/.test(password);
        if (analysis.hasSpecial) score += 15;

        analysis.isCommon = this.commonPasswords.has(password.toLowerCase());
        if (analysis.isCommon) score -= 50;

        analysis.entropy = this.calculateEntropy(password);
        score += analysis.entropy;

        analysis.bruteforceTime = this.calculateBruteforceTime(password);

        return { score: Math.max(0, Math.min(100, score)), analysis };
    }

    calculateEntropy(password) {
        if (!password) return 0;
        
        let charsetSize = 0;
        if (/[a-z]/.test(password)) charsetSize += 26;
        if (/[A-Z]/.test(password)) charsetSize += 26;
        if (/\d/.test(password)) charsetSize += 10;
        if (/[^a-zA-Z0-9]/.test(password)) charsetSize += 32;

        return password.length * Math.log2(charsetSize);
    }

    calculateBruteforceTime(password) {
        const guessesPerSecond = 1e9;
        const entropy = Math.pow(2, this.calculateEntropy(password));
        const seconds = entropy / guessesPerSecond;
        return this.formatTime(seconds);
    }

    formatTime(seconds) {
        if (this.currentLanguage === 'en') {
            if (seconds < 1) return 'instantly';
            if (seconds < 60) return `${Math.round(seconds)} seconds`;
            
            const minutes = seconds / 60;
            if (minutes < 60) return `${Math.round(minutes)} minutes`;
            
            const hours = minutes / 60;
            if (hours < 24) return `${Math.round(hours)} hours`;
            
            const days = hours / 24;
            if (days < 30) return `${Math.round(days)} days`;
            
            const years = days / 365;
            return `${years.toFixed(1)} years`;
        } else {
            if (seconds < 1) return 'anında';
            if (seconds < 60) return `${Math.round(seconds)} saniye`;
            
            const minutes = seconds / 60;
            if (minutes < 60) return `${Math.round(minutes)} dakika`;
            
            const hours = minutes / 60;
            if (hours < 24) return `${Math.round(hours)} saat`;
            
            const days = hours / 24;
            if (days < 30) return `${Math.round(days)} gün`;
            
            const years = days / 365;
            return `${years.toFixed(1)} yıl`;
        }
    }

    
    async checkPasswordBreaches(password) {
        if (!password || password.length < 3) {
            return { breached: false, count: 0 };
        }

        const cacheKey = password;
        if (this.breachCache.has(cacheKey)) {
            return this.breachCache.get(cacheKey);
        }

        try {
            const encoder = new TextEncoder();
            const data = encoder.encode(password);
            const hashBuffer = await crypto.subtle.digest('SHA-1', data);
            const hashArray = Array.from(new Uint8Array(hashBuffer));
            const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase();
            
            const prefix = hashHex.substring(0, 5);
            const suffix = hashHex.substring(5);

            const response = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`, {
                headers: {
                    'User-Agent': 'Password-Strength-Analyzer-v1'
                }
            });

            if (!response.ok) {
                throw new Error('API error');
            }

            const dataText = await response.text();
            const lines = dataText.split('\n');
            
            let breachCount = 0;
            for (const line of lines) {
                const [lineSuffix, count] = line.split(':');
                if (lineSuffix === suffix) {
                    breachCount = parseInt(count, 10);
                    break;
                }
            }

            const result = {
                breached: breachCount > 0,
                count: breachCount,
                hash: hashHex
            };

            this.breachCache.set(cacheKey, result);
            return result;

        } catch (error) {
            console.warn('HIBP API error:', error);
            return { breached: false, count: 0, error: true };
        }
    }

    // 🆕 Çoklu Şifre Karşılaştırması
    async addPasswordToComparison() {
        const password = document.getElementById('passwordInput').value;
        if (!password) {
            alert(this.currentLanguage === 'en' 
                ? 'Please enter a password first!' 
                : 'Lütfen önce bir şifre girin!');
            return;
        }

        if (this.passwordComparison.length >= 3) {
            alert(this.currentLanguage === 'en' 
                ? 'Maximum 3 passwords can be compared!' 
                : 'Maksimum 3 şifre karşılaştırılabilir!');
            return;
        }

        const strength = this.calculateStrength(password);
        const breachData = await this.checkPasswordBreaches(password);
        
        const comparisonItem = {
            password: password.substring(0, 3) + '***' + password.substring(password.length - 2),
            fullPassword: password,
            strength: strength.score,
            entropy: strength.analysis.entropy,
            breachCount: breachData.count,
            timestamp: new Date().toLocaleTimeString()
        };

        this.passwordComparison.push(comparisonItem);
        this.updateComparisonDisplay();
        this.saveToLocalStorage();
    }

    clearComparison() {
        this.passwordComparison = [];
        this.updateComparisonDisplay();
        this.saveToLocalStorage();
    }

    updateComparisonDisplay() {
        const comparisonResults = document.getElementById('comparisonResults');
        
        if (this.passwordComparison.length === 0) {
            comparisonResults.innerHTML = `
                <div class="comparison-empty">
                    ${this.currentLanguage === 'en' 
                        ? 'No passwords added for comparison' 
                        : 'Karşılaştırma için şifre eklenmedi'}
                </div>
            `;
            return;
        }

        comparisonResults.innerHTML = this.passwordComparison.map((item, index) => {
            let strengthClass = 'strength-weak';
            if (item.strength >= 60) strengthClass = 'strength-strong';
            else if (item.strength >= 30) strengthClass = 'strength-medium';

            let breachWarning = '';
            if (item.breachCount > 0) {
                breachWarning = this.currentLanguage === 'en'
                    ? `<div class="breach-warning">⚠️ Found in ${item.breachCount} breaches</div>`
                    : `<div class="breach-warning">⚠️ ${item.breachCount} ihlalde bulundu</div>`;
            }

            return `
                <div class="comparison-item">
                    <div class="comparison-header">
                        <strong>${this.currentLanguage === 'en' ? 'Password' : 'Şifre'} ${index + 1}</strong>
                        <span class="comparison-strength ${strengthClass}">${Math.round(item.strength)}</span>
                    </div>
                    <div class="comparison-details">
                        <div>${item.password}</div>
                        <div class="comparison-stats">
                            <span>${this.currentLanguage === 'en' ? 'Entropy' : 'Entropi'}: ${item.entropy.toFixed(1)}</span>
                            <span>${item.timestamp}</span>
                        </div>
                        ${breachWarning}
                    </div>
                </div>
            `;
        }).join('') + `
            <div class="comparison-summary">
                <strong>${this.currentLanguage === 'en' ? 'Comparison Summary' : 'Karşılaştırma Özeti'}:</strong>
                ${this.getComparisonSummary()}
            </div>
        `;
    }

    getComparisonSummary() {
        if (this.passwordComparison.length === 0) return '';
        
        const strongest = this.passwordComparison.reduce((max, item) => 
            item.strength > max.strength ? item : max
        );
        
        const weakest = this.passwordComparison.reduce((min, item) => 
            item.strength < min.strength ? item : min
        );

        if (this.currentLanguage === 'en') {
            return `Strongest: Password ${this.passwordComparison.indexOf(strongest) + 1} (${Math.round(strongest.strength)}), 
                    Weakest: Password ${this.passwordComparison.indexOf(weakest) + 1} (${Math.round(weakest.strength)})`;
        } else {
            return `En Güçlü: Şifre ${this.passwordComparison.indexOf(strongest) + 1} (${Math.round(strongest.strength)}), 
                    En Zayıf: Şifre ${this.passwordComparison.indexOf(weakest) + 1} (${Math.round(weakest.strength)})`;
        }
    }

    
    generatePasswordRules() {
        const ruleSettings = {
            minLength: parseInt(document.getElementById('policyMinLength').value) || 12,
            requireUpper: document.getElementById('policyRequireUpper').checked,
            requireLower: document.getElementById('policyRequireLower').checked,
            requireNumbers: document.getElementById('policyRequireNumbers').checked,
            requireSpecial: document.getElementById('policyRequireSpecial').checked,
            maxAge: parseInt(document.getElementById('policyMaxAge').value) || 90,
            preventReuse: document.getElementById('policyPreventReuse').checked
        };

        const rules = this.createRuleObject(ruleSettings);
        this.displayPasswordRules(rules);
    }

    createRuleObject(settings) {
        const requirements = [];
        
        if (this.currentLanguage === 'en') {
            requirements.push(`Minimum ${settings.minLength} characters`);
            if (settings.requireUpper) requirements.push('Uppercase letters required');
            if (settings.requireLower) requirements.push('Lowercase letters required');
            if (settings.requireNumbers) requirements.push('Numbers required');
            if (settings.requireSpecial) requirements.push('Special characters required');
            requirements.push(`Maximum password age: ${settings.maxAge} days`);
            if (settings.preventReuse) requirements.push('Password reuse prevented');
        } else {
            requirements.push(`Minimum ${settings.minLength} karakter`);
            if (settings.requireUpper) requirements.push('Büyük harf zorunlu');
            if (settings.requireLower) requirements.push('Küçük harf zorunlu');
            if (settings.requireNumbers) requirements.push('Rakam zorunlu');
            if (settings.requireSpecial) requirements.push('Özel karakter zorunlu');
            requirements.push(`Maksimum şifre ömrü: ${settings.maxAge} gün`);
            if (settings.preventReuse) requirements.push('Şifre tekrarı engellendi');
        }

        return {
            settings: settings,
            requirements: requirements,
            generatedAt: new Date().toLocaleString()
        };
    }

    displayPasswordRules(rules) {
        const policyResults = document.getElementById('policyResults');
        
        policyResults.innerHTML = `
            <div class="policy-header">
                <h4>${this.currentLanguage === 'en' ? 'Generated Password Rules' : 'Oluşturulan Şifre Kuralları'}</h4>
                <div class="policy-meta">${this.currentLanguage === 'en' ? 'Generated' : 'Oluşturulma'}: ${rules.generatedAt}</div>
            </div>
            <div class="policy-requirements">
                ${rules.requirements.map(req => `
                    <div class="policy-item">⚙️ ${req}</div>
                `).join('')}
            </div>
            <div class="policy-actions">
                <button onclick="passwordAnalyzer.exportRulesAsJSON()" class="export-btn">
                    ${this.currentLanguage === 'en' ? '📋 Export as JSON' : '📋 JSON Olarak Dışa Aktar'}
                </button>
                <button onclick="passwordAnalyzer.copyRulesToClipboard()" class="export-btn">
                    ${this.currentLanguage === 'en' ? '📄 Copy as Text' : '📄 Metin Olarak Kopyala'}
                </button>
            </div>
        `;
    }

    applyPasswordRules() {
        const ruleSettings = {
            minLength: parseInt(document.getElementById('policyMinLength').value) || 12,
            requireUpper: document.getElementById('policyRequireUpper').checked,
            requireLower: document.getElementById('policyRequireLower').checked,
            requireNumbers: document.getElementById('policyRequireNumbers').checked,
            requireSpecial: document.getElementById('policyRequireSpecial').checked
        };

        const password = document.getElementById('passwordInput').value;
        const validation = this.validatePasswordAgainstRules(password, ruleSettings);
        
        this.displayRuleValidation(validation);
    }

    validatePasswordAgainstRules(password, rules) {
        const errors = [];
        const warnings = [];

        if (this.currentLanguage === 'en') {
            if (password.length < rules.minLength) {
                errors.push(`Password must be at least ${rules.minLength} characters long`);
            }
            if (rules.requireUpper && !/[A-Z]/.test(password)) {
                errors.push('Password must contain uppercase letters');
            }
            if (rules.requireLower && !/[a-z]/.test(password)) {
                errors.push('Password must contain lowercase letters');
            }
            if (rules.requireNumbers && !/\d/.test(password)) {
                errors.push('Password must contain numbers');
            }
            if (rules.requireSpecial && !/[^A-Za-z0-9]/.test(password)) {
                errors.push('Password must contain special characters');
            }
            
            if (password.length < 8) {
                warnings.push('Consider using a longer password for better security');
            }
            if (!/[A-Z]/.test(password) && !rules.requireUpper) {
                warnings.push('Adding uppercase letters improves security');
            }
            if (!/\d/.test(password) && !rules.requireNumbers) {
                warnings.push('Adding numbers improves security');
            }
        } else {
            if (password.length < rules.minLength) {
                errors.push(`Şifre en az ${rules.minLength} karakter olmalı`);
            }
            if (rules.requireUpper && !/[A-Z]/.test(password)) {
                errors.push('Şifre büyük harf içermeli');
            }
            if (rules.requireLower && !/[a-z]/.test(password)) {
                errors.push('Şifre küçük harf içermeli');
            }
            if (rules.requireNumbers && !/\d/.test(password)) {
                errors.push('Şifre rakam içermeli');
            }
            if (rules.requireSpecial && !/[^A-Za-z0-9]/.test(password)) {
                errors.push('Şifre özel karakter içermeli');
            }
            
            if (password.length < 8) {
                warnings.push('Daha iyi güvenlik için daha uzun şifre kullanmayı düşünün');
            }
            if (!/[A-Z]/.test(password) && !rules.requireUpper) {
                warnings.push('Büyük harf eklemek güvenliği artırır');
            }
            if (!/\d/.test(password) && !rules.requireNumbers) {
                warnings.push('Rakam eklemek güvenliği artırır');
            }
        }

        return {
            isValid: errors.length === 0,
            errors: errors,
            warnings: warnings,
            score: this.calculateStrength(password).score
        };
    }

    displayRuleValidation(validation) {
        const policyValidation = document.getElementById('policyValidation');
        
        let html = '';
        
        if (validation.isValid) {
            html += `
                <div class="validation-result valid">
                    <strong>✅ ${this.currentLanguage === 'en' ? 'Password meets all rules' : 'Şifre tüm kuralları karşılıyor'}</strong>
                    <div>${this.currentLanguage === 'en' ? 'Score' : 'Skor'}: ${Math.round(validation.score)}/100</div>
                </div>
            `;
        } else {
            html += `
                <div class="validation-result invalid">
                    <strong>❌ ${this.currentLanguage === 'en' ? 'Password does not meet all rules' : 'Şifre tüm kuralları karşılamıyor'}</strong>
                    <div class="validation-errors">
                        ${validation.errors.map(error => `<div>• ${error}</div>`).join('')}
                    </div>
                </div>
            `;
        }

        if (validation.warnings.length > 0) {
            html += `
                <div class="validation-warnings">
                    <strong>⚠️ ${this.currentLanguage === 'en' ? 'Suggestions' : 'Öneriler'}:</strong>
                    ${validation.warnings.map(warning => `<div>• ${warning}</div>`).join('')}
                </div>
            `;
        }

        policyValidation.innerHTML = html;
    }

    exportRulesAsJSON() {
        const ruleSettings = {
            minLength: parseInt(document.getElementById('policyMinLength').value) || 12,
            requireUpper: document.getElementById('policyRequireUpper').checked,
            requireLower: document.getElementById('policyRequireLower').checked,
            requireNumbers: document.getElementById('policyRequireNumbers').checked,
            requireSpecial: document.getElementById('policyRequireSpecial').checked,
            maxAge: parseInt(document.getElementById('policyMaxAge').value) || 90,
            preventReuse: document.getElementById('policyPreventReuse').checked,
            generatedAt: new Date().toISOString(),
            generatedBy: 'Password Strength Analyzer - Rule Engine'
        };

        const blob = new Blob([JSON.stringify(ruleSettings, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        
        const a = document.createElement('a');
        a.href = url;
        a.download = 'password-rules.json';
        a.click();
        
        URL.revokeObjectURL(url);
        
        alert(this.currentLanguage === 'en' 
            ? 'Password rules exported as JSON!' 
            : 'Şifre kuralları JSON olarak dışa aktarıldı!');
    }

    copyRulesToClipboard() {
        const ruleSettings = {
            minLength: parseInt(document.getElementById('policyMinLength').value) || 12,
            requireUpper: document.getElementById('policyRequireUpper').checked,
            requireLower: document.getElementById('policyRequireLower').checked,
            requireNumbers: document.getElementById('policyRequireNumbers').checked,
            requireSpecial: document.getElementById('policyRequireSpecial').checked,
            maxAge: parseInt(document.getElementById('policyMaxAge').value) || 90,
            preventReuse: document.getElementById('policyPreventReuse').checked
        };

        const rules = this.createRuleObject(ruleSettings);
        const rulesText = rules.requirements.join('\n• ');
        
        const fullText = this.currentLanguage === 'en'
            ? `Password Rule Engine - Generated Rules:\n• ${rulesText}\n\nGenerated: ${rules.generatedAt}`
            : `Şifre Kuralı Motoru - Oluşturulan Kurallar:\n• ${rulesText}\n\nOluşturulma: ${rules.generatedAt}`;

        navigator.clipboard.writeText(fullText).then(() => {
            alert(this.currentLanguage === 'en' 
                ? 'Password rules copied to clipboard!' 
                : 'Şifre kuralları panoya kopyalandı!');
        });
    }

    updateAllDisplays(strength, password, breachData) {
        this.updateStrengthMeter(strength.score);
        this.updateAnalysisResults(strength.analysis, breachData);
        this.updateBruteforceResult(strength.analysis.bruteforceTime);
        this.updateHealthScore(password, strength, breachData);
        this.updateSecurityAudit(password, strength, breachData);
        this.updatePatternAnalysis(password);
        this.updateHistoryDisplay();
        this.updateCharts(password);
    }

    updateStrengthMeter(score) {
        const strengthBar = document.getElementById('strengthBar');
        const strengthText = document.getElementById('strengthText');

        let percentage = Math.min(Math.max(score, 0), 100);
        let color = '#ff4d4d';
        
        let text;
        if (this.currentLanguage === 'en') {
            if (percentage < 25) text = 'Very Weak';
            else if (percentage < 50) text = 'Weak';
            else if (percentage < 75) text = 'Medium';
            else if (percentage < 90) text = 'Strong';
            else text = 'Very Strong';
        } else {
            if (percentage < 25) text = 'Çok Zayıf';
            else if (percentage < 50) text = 'Zayıf';
            else if (percentage < 75) text = 'Orta';
            else if (percentage < 90) text = 'Güçlü';
            else text = 'Çok Güçlü';
        }

        if (percentage >= 25) color = '#ffa500';
        if (percentage >= 50) color = '#ffff00';
        if (percentage >= 75) color = '#90ee90';
        if (percentage >= 90) color = '#32cd32';

        strengthBar.style.width = `${percentage}%`;
        strengthBar.style.backgroundColor = color;
        
        if (this.currentLanguage === 'en') {
            strengthText.textContent = `Password strength: ${text} (${Math.round(percentage)}/100)`;
        } else {
            strengthText.textContent = `Şifre gücü: ${text} (${Math.round(percentage)}/100)`;
        }
        
        strengthText.style.color = color;
    }

    updateAnalysisResults(analysis, breachData) {
        const resultsDiv = document.getElementById('analysisResults');
        
        if (this.currentLanguage === 'en') {
            const checks = [
                { text: 'At least 8 characters', valid: analysis.length },
                { text: 'Contains uppercase letters', valid: analysis.hasUpper },
                { text: 'Contains lowercase letters', valid: analysis.hasLower },
                { text: 'Contains numbers', valid: analysis.hasNumber },
                { text: 'Contains special characters', valid: analysis.hasSpecial },
                { text: 'Not a common password', valid: !analysis.isCommon },
                { 
                    text: breachData.breached ? 
                        `Not found in data breaches (found in ${breachData.count} breaches)` : 
                        'Not found in data breaches', 
                    valid: !breachData.breached 
                }
            ];

            resultsDiv.innerHTML = checks.map(check => `
                <div class="analysis-item ${check.valid ? 'valid' : 'invalid'}">
                    <span>${check.text}</span>
                    <span>${check.valid ? '✅' : '❌'}</span>
                </div>
            `).join('') + `
                <div class="analysis-item">
                    <span>Entropy (bits):</span>
                    <span>${analysis.entropy.toFixed(2)}</span>
                </div>
            `;
        } else {
            const checks = [
                { text: 'En az 8 karakter', valid: analysis.length },
                { text: 'Büyük harf içeriyor', valid: analysis.hasUpper },
                { text: 'Küçük harf içeriyor', valid: analysis.hasLower },
                { text: 'Rakam içeriyor', valid: analysis.hasNumber },
                { text: 'Özel karakter içeriyor', valid: analysis.hasSpecial },
                { text: 'Yaygın şifre değil', valid: !analysis.isCommon },
                { 
                    text: breachData.breached ? 
                        `Veri ihlallerinde bulunmadı (${breachData.count} ihlalde görüldü)` : 
                        'Veri ihlallerinde bulunmadı', 
                    valid: !breachData.breached 
                }
            ];

            resultsDiv.innerHTML = checks.map(check => `
                <div class="analysis-item ${check.valid ? 'valid' : 'invalid'}">
                    <span>${check.text}</span>
                    <span>${check.valid ? '✅' : '❌'}</span>
                </div>
            `).join('') + `
                <div class="analysis-item">
                    <span>Entropi (bit):</span>
                    <span>${analysis.entropy.toFixed(2)}</span>
                </div>
            `;
        }
    }

    updateBruteforceResult(time) {
        const element = document.getElementById('bruteforceResult');
        if (element) {
            if (this.currentLanguage === 'en') {
                element.textContent = `Estimated time to crack: ${time}`;
            } else {
                element.textContent = `Tahmini kırılma süresi: ${time}`;
            }
        }
    }

    updateHealthScore(password, strength, breachData) {
        const healthScoreEl = document.getElementById('healthScore');
        const healthBreakdownEl = document.getElementById('healthBreakdown');
        
        let healthScore = strength.score;
        const breakdown = [];

        if (password.length >= 12) {
            healthScore += 10;
            breakdown.push(this.currentLanguage === 'en' ? "✓ Long password (+10)" : "✓ Uzun şifre (+10)");
        }

        const varietyCount = [strength.analysis.hasUpper, strength.analysis.hasLower, 
                             strength.analysis.hasNumber, strength.analysis.hasSpecial].filter(Boolean).length;
        if (varietyCount >= 3) {
            healthScore += 15;
            breakdown.push(this.currentLanguage === 'en' ? "✓ Good character variety (+15)" : "✓ İyi karakter çeşitliliği (+15)");
        }

        if (strength.analysis.isCommon) {
            healthScore -= 30;
            breakdown.push(this.currentLanguage === 'en' ? "✗ Common password (-30)" : "✗ Yaygın şifre (-30)");
        }

        if (breachData.breached) {
            healthScore -= 40;
            if (this.currentLanguage === 'en') {
                breakdown.push(`✗ Found in ${breachData.count} data breaches (-40)`);
            } else {
                breakdown.push(`✗ ${breachData.count} veri ihlalinde bulundu (-40)`);
            }
        } else if (!breachData.error) {
            healthScore += 20;
            breakdown.push(this.currentLanguage === 'en' ? "✓ No data breaches found (+20)" : "✓ Veri ihlali bulunamadı (+20)");
        }

        if (strength.analysis.entropy > 40) {
            healthScore += 10;
            breakdown.push(this.currentLanguage === 'en' ? "✓ High entropy (+10)" : "✓ Yüksek entropi (+10)");
        }

        healthScore = Math.max(0, Math.min(100, healthScore));

        healthScoreEl.textContent = Math.round(healthScore);
        
        const scoreCircle = healthScoreEl.parentElement;
        if (healthScore >= 80) {
            scoreCircle.style.background = 'conic-gradient(#51cf66 0%, #51cf66 100%)';
        } else if (healthScore >= 60) {
            scoreCircle.style.background = 'conic-gradient(#ffd43b 0%, #ffd43b 100%)';
        } else {
            scoreCircle.style.background = 'conic-gradient(#ff6b6b 0%, #ff6b6b 100%)';
        }
        
        healthBreakdownEl.innerHTML = breakdown.map(item => `
            <div class="breakdown-item">${item}</div>
        `).join('');
    }

    updateSecurityAudit(password, strength, breachData) {
        const auditResultsEl = document.getElementById('auditResults');

        const auditItems = [];

        if (password.length < 8) {
            auditItems.push({
                level: 'high',
                message: this.currentLanguage === 'en' 
                    ? 'Password is too short (minimum 8 characters)'
                    : 'Şifre çok kısa (minimum 8 karakter)',
                suggestion: this.currentLanguage === 'en' 
                    ? 'Use a longer password'
                    : 'Daha uzun şifre kullanın'
            });
        } else if (password.length >= 12) {
            auditItems.push({
                level: 'good', 
                message: this.currentLanguage === 'en' 
                    ? 'Password length is sufficient'
                    : 'Şifre uzunluğu yeterli',
                suggestion: ''
            });
        }

        const varietyCount = [strength.analysis.hasUpper, strength.analysis.hasLower, 
                             strength.analysis.hasNumber, strength.analysis.hasSpecial].filter(Boolean).length;
        
        if (varietyCount < 3) {
            auditItems.push({
                level: 'medium',
                message: this.currentLanguage === 'en' 
                    ? `Only ${varietyCount} character type${varietyCount === 1 ? '' : 's'} used`
                    : `Sadece ${varietyCount} karakter türü kullanılmış`,
                suggestion: this.currentLanguage === 'en' 
                    ? 'Use more character variety'
                    : 'Daha çeşitli karakter kullanın'
            });
        } else {
            auditItems.push({
                level: 'good',
                message: this.currentLanguage === 'en' 
                    ? 'Good character variety'
                    : 'İyi karakter çeşitliliği',
                suggestion: ''
            });
        }

        if (strength.analysis.isCommon) {
            auditItems.push({
                level: 'high',
                message: this.currentLanguage === 'en' 
                    ? 'This password is very common'
                    : 'Bu şifre çok yaygın kullanılıyor',
                suggestion: this.currentLanguage === 'en' 
                    ? 'Choose a less common password'
                    : 'Daha az bilinen şifre seçin'
            });
        }

        if (breachData.breached) {
            auditItems.push({
                level: 'high',
                message: this.currentLanguage === 'en' 
                    ? `This password was found in ${breachData.count} data breaches`
                    : `Bu şifre ${breachData.count} veri ihlalinde bulundu`,
                suggestion: this.currentLanguage === 'en' 
                    ? 'Change this password immediately!'
                    : 'Bu şifreyi hemen değiştirin!'
            });
        } else if (!breachData.error) {
            auditItems.push({
                level: 'good',
                message: this.currentLanguage === 'en' 
                    ? 'Password not found in known data breaches'
                    : 'Şifre bilinen veri ihlallerinde bulunamadı',
                suggestion: ''
            });
        }

        if (strength.analysis.entropy < 30) {
            auditItems.push({
                level: 'medium',
                message: this.currentLanguage === 'en' 
                    ? 'Password is too predictable'
                    : 'Şifre çok tahmin edilebilir',
                suggestion: this.currentLanguage === 'en' 
                    ? 'Create a more random password'
                    : 'Daha rastgele şifre oluşturun'
            });
        }

        auditResultsEl.innerHTML = auditItems.map(item => `
            <div class="audit-item ${item.level}">
                <strong>${item.message}</strong>
                ${item.suggestion ? `<div>💡 ${item.suggestion}</div>` : ''}
            </div>
        `).join('');
    }

    updatePatternAnalysis(password) {
        const patternResultsEl = document.getElementById('patternResults');

        const patterns = this.detectPatterns(password);
        
        if (patterns.length === 0) {
            patternResultsEl.innerHTML = '<div class="pattern-item">✅ ' + 
                (this.currentLanguage === 'en' ? 'No patterns detected' : 'Pattern tespit edilmedi') + '</div>';
        } else {
            patternResultsEl.innerHTML = patterns.map(pattern => `
                <div class="pattern-item">⚠️ ${pattern}</div>
            `).join('');
        }
    }

    detectPatterns(password) {
        const patterns = [];

        if (/(abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz)/i.test(password)) {
            patterns.push(this.currentLanguage === 'en' 
                ? "Sequential letter pattern detected"
                : "Sıralı harf patterni tespit edildi");
        }

        if (/(012|123|234|345|456|567|678|789|890)/.test(password)) {
            patterns.push(this.currentLanguage === 'en' 
                ? "Sequential number pattern detected"
                : "Sıralı rakam patterni tespit edildi");
        }

        if (/(.)\1{2,}/.test(password)) {
            patterns.push(this.currentLanguage === 'en' 
                ? "Repeated characters detected"
                : "Tekrarlanan karakterler tespit edildi");
        }

        const keyboardPatterns = ['qwerty', 'asdfgh', 'zxcvbn', '123456'];
        for (const pattern of keyboardPatterns) {
            if (password.toLowerCase().includes(pattern)) {
                patterns.push(this.currentLanguage === 'en' 
                    ? "Keyboard pattern detected: " + pattern
                    : "Klavye patterni tespit edildi: " + pattern);
                break;
            }
        }

        return patterns;
    }

    toggleTheme() {
        this.currentTheme = this.currentTheme === 'light' ? 'dark' : 'light';
        document.body.classList.toggle('dark-mode', this.currentTheme === 'dark');
        
        const themeToggle = document.getElementById('themeToggle');
        if (this.currentLanguage === 'en') {
            themeToggle.textContent = this.currentTheme === 'light' ? '🌙 Dark Mode' : '☀️ Light Mode';
        } else {
            themeToggle.textContent = this.currentTheme === 'light' ? '🌙 Koyu Mod' : '☀️ Açık Mod';
        }
        
        this.saveToLocalStorage();
    }

    toggleLanguage() {
        this.currentLanguage = this.currentLanguage === 'tr' ? 'en' : 'tr';
        this.updateAllTexts();
        
        const currentPassword = document.getElementById('passwordInput').value;
        if (currentPassword) {
            this.analyzePassword(currentPassword);
        }
        
        this.saveToLocalStorage();
    }

    updateAllTexts() {
        const lang = this.currentLanguage;
        
        document.getElementById('languageToggle').textContent = `🌐 ${lang.toUpperCase()}`;
        
        const themeToggle = document.getElementById('themeToggle');
        themeToggle.textContent = this.currentTheme === 'light' 
            ? (lang === 'en' ? '🌙 Dark Mode' : '🌙 Koyu Mod')
            : (lang === 'en' ? '☀️ Light Mode' : '☀️ Açık Mod');

        document.getElementById('mainTitle').textContent = lang === 'en' 
            ? '🔐 Password Strength Analyzer' 
            : '🔐 Şifre Güç Analiz Aracı';

        document.getElementById('analysisTitle').textContent = lang === 'en' 
            ? '📊 Detailed Analysis' 
            : '📊 Detaylı Analiz';

        document.getElementById('healthTitle').textContent = lang === 'en' 
            ? '🏥 Password Health Score' 
            : '🏥 Şifre Sağlık Skoru';

        document.getElementById('auditTitle').textContent = lang === 'en' 
            ? '🔍 Security Audit' 
            : '🔍 Güvenlik Denetimi';

        document.getElementById('patternTitle').textContent = lang === 'en' 
            ? '🎯 Pattern Analysis' 
            : '🎯 Pattern Analizi';

        document.getElementById('chartsTitle').textContent = lang === 'en' 
            ? '📈 Analytics & Reports' 
            : '📈 Analitik & Raporlar';

        document.getElementById('historyTitle').textContent = lang === 'en' 
            ? '📜 Password History' 
            : '📜 Şifre Geçmişi';

        document.getElementById('bruteforceTitle').textContent = lang === 'en' 
            ? '🔓 Bruteforce Simulation' 
            : '🔓 Bruteforce Simülasyonu';

        document.getElementById('generatorTitle').textContent = lang === 'en' 
            ? '🎲 Password Generator' 
            : '🎲 Şifre Üretici';

        // 🆕 Yeni başlıklar - Password Rule Engine
        document.getElementById('comparisonTitle').textContent = lang === 'en' 
            ? '🔄 Password Comparison' 
            : '🔄 Şifre Karşılaştırması';

        document.getElementById('policyTitle').textContent = lang === 'en' 
            ? '⚙️ Password Rule Engine' 
            : '⚙️ Şifre Kuralı Motoru';

        document.getElementById('strengthChartTitle').textContent = lang === 'en' 
            ? 'Strength Trend' 
            : 'Güç Trendi';

        document.getElementById('characterChartTitle').textContent = lang === 'en' 
            ? 'Character Distribution' 
            : 'Karakter Dağılımı';

        document.getElementById('attackTypeLabel').textContent = lang === 'en' 
            ? 'Attack Type:' 
            : 'Saldırı Tipi:';

        document.getElementById('attackSpeedLabel').textContent = lang === 'en' 
            ? 'Attack Speed:' 
            : 'Saldırı Hızı:';

       
        document.getElementById('addComparePassword').textContent = lang === 'en' 
            ? 'Add to Comparison' 
            : 'Karşılaştırmaya Ekle';

        document.getElementById('clearComparison').textContent = lang === 'en' 
            ? 'Clear Comparison' 
            : 'Karşılaştırmayı Temizle';

        document.getElementById('generatePolicy').textContent = lang === 'en' 
            ? 'Generate Rules' 
            : 'Kuralları Oluştur';

        document.getElementById('applyPolicy').textContent = lang === 'en' 
            ? 'Apply Rules' 
            : 'Kuralları Uygula';

        document.getElementById('policyMinLengthLabel').textContent = lang === 'en' 
            ? 'Minimum Length:' 
            : 'Minimum Uzunluk:';

        document.getElementById('policyRequireUpperLabel').textContent = lang === 'en' 
            ? 'Require Uppercase' 
            : 'Büyük Harf Zorunlu';

        document.getElementById('policyRequireLowerLabel').textContent = lang === 'en' 
            ? 'Require Lowercase' 
            : 'Küçük Harf Zorunlu';

        document.getElementById('policyRequireNumbersLabel').textContent = lang === 'en' 
            ? 'Require Numbers' 
            : 'Rakam Zorunlu';

        document.getElementById('policyRequireSpecialLabel').textContent = lang === 'en' 
            ? 'Require Special Characters' 
            : 'Özel Karakter Zorunlu';

        document.getElementById('policyMaxAgeLabel').textContent = lang === 'en' 
            ? 'Maximum Age (days):' 
            : 'Maksimum Ömür (gün):';

        document.getElementById('policyPreventReuseLabel').textContent = lang === 'en' 
            ? 'Prevent Password Reuse' 
            : 'Şifre Tekrarını Engelle';

        document.getElementById('generateBtn').textContent = lang === 'en' 
            ? 'Generate New Password' 
            : 'Yeni Şifre Üret';

        document.getElementById('copyBtn').textContent = lang === 'en' 
            ? 'Copy' 
            : 'Kopyala';

        document.getElementById('startSimulation').textContent = lang === 'en' 
            ? 'Start Simulation' 
            : 'Simülasyonu Başlat';

        document.getElementById('exportPDF').textContent = lang === 'en' 
            ? '📄 Export PDF' 
            : '📄 PDF İndir';

        document.getElementById('exportCSV').textContent = lang === 'en' 
            ? '📊 Export CSV' 
            : '📊 CSV İndir';

        document.getElementById('passwordInput').placeholder = lang === 'en' 
            ? 'Enter your password...' 
            : 'Şifrenizi girin...';

        const historyEmpty = document.querySelector('.history-empty');
        if (historyEmpty) {
            historyEmpty.textContent = lang === 'en' 
                ? 'No password analyzed yet' 
                : 'Henüz şifre analiz edilmedi';
        }

        const attackTypeSelect = document.getElementById('attackType');
        if (attackTypeSelect) {
            attackTypeSelect.innerHTML = lang === 'en' 
                ? `<option value="bruteforce">Bruteforce</option>
                   <option value="dictionary">Dictionary Attack</option>`
                : `<option value="bruteforce">Bruteforce</option>
                   <option value="dictionary">Sözlük Saldırısı</option>`;
        }

        const attackSpeedSelect = document.getElementById('attackSpeed');
        if (attackSpeedSelect) {
            attackSpeedSelect.innerHTML = lang === 'en' 
                ? `<option value="1e6">Normal PC (1M guess/s)</option>
                   <option value="1e9">Gaming PC (1B guess/s)</option>
                   <option value="1e12">GPU Cluster (1T guess/s)</option>`
                : `<option value="1e6">Normal PC (1M tahmin/s)</option>
                   <option value="1e9">Gaming PC (1B tahmin/s)</option>
                   <option value="1e12">GPU Cluster (1T tahmin/s)</option>`;
        }

        if (this.charts.strength) {
            this.charts.strength.data.datasets[0].label = lang === 'en' ? 'Password Strength' : 'Şifre Gücü';
            this.charts.strength.update();
        }

        if (this.charts.character) {
            this.charts.character.data.labels = lang === 'en' 
                ? ['Uppercase', 'Lowercase', 'Numbers', 'Special']
                : ['Büyük Harf', 'Küçük Harf', 'Rakamlar', 'Özel'];
            this.charts.character.update();
        }

        
        this.updateComparisonDisplay();
        const policyResults = document.getElementById('policyResults');
        if (policyResults.innerHTML.includes('Generated Password Rules') || 
            policyResults.innerHTML.includes('Oluşturulan Şifre Kuralları')) {
            this.generatePasswordRules();
        }
    }

    saveToLocalStorage() {
        const data = {
            theme: this.currentTheme,
            language: this.currentLanguage,
            passwordHistory: this.passwordHistory.slice(-10),
            passwordComparison: this.passwordComparison,
            lastUpdated: new Date().toISOString()
        };
        
        try {
            localStorage.setItem('passwordAnalyzerData', JSON.stringify(data));
        } catch (error) {
            console.error('LocalStorage error:', error);
        }
    }

    loadFromLocalStorage() {
        try {
            const saved = localStorage.getItem('passwordAnalyzerData');
            if (saved) {
                const data = JSON.parse(saved);
                
                if (data.theme) {
                    this.currentTheme = data.theme;
                    document.body.classList.toggle('dark-mode', this.currentTheme === 'dark');
                }
                
                if (data.language) {
                    this.currentLanguage = data.language;
                }
                
                if (data.passwordHistory) {
                    this.passwordHistory = data.passwordHistory;
                }

                if (data.passwordComparison) {
                    this.passwordComparison = data.passwordComparison;
                }
            }
        } catch (error) {
            console.error('LocalStorage load error:', error);
        }
    }

    addToHistory(password, strength) {
        const historyItem = {
            password: password.substring(0, 3) + '***',
            strength: strength.score,
            entropy: strength.analysis.entropy,
            timestamp: new Date().toISOString()
        };
        
        this.passwordHistory.push(historyItem);
        
        if (this.passwordHistory.length > 10) {
            this.passwordHistory = this.passwordHistory.slice(-10);
        }
        
        this.saveToLocalStorage();
        this.updateHistoryDisplay();
    }

    updateHistoryDisplay() {
        const historyList = document.getElementById('historyList');
        
        if (this.passwordHistory.length === 0) {
            historyList.innerHTML = '<div class="history-empty">' + 
                (this.currentLanguage === 'en' ? 'No password analyzed yet' : 'Henüz şifre analiz edilmedi') + 
                '</div>';
            return;
        }
        
        historyList.innerHTML = this.passwordHistory.slice().reverse().map(item => {
            let strengthClass = 'strength-weak';
            if (item.strength >= 60) strengthClass = 'strength-strong';
            else if (item.strength >= 30) strengthClass = 'strength-medium';
            
            const time = new Date(item.timestamp).toLocaleTimeString();
            
            return `
                <div class="history-item">
                    <div>
                        <strong>${item.password}</strong>
                        <div style="font-size: 12px; color: #666;">${time} • ${this.currentLanguage === 'en' ? 'Entropy' : 'Entropi'}: ${item.entropy.toFixed(1)}</div>
                    </div>
                    <div class="history-strength ${strengthClass}">
                        ${Math.round(item.strength)}
                    </div>
                </div>
            `;
        }).join('');
    }

    initCharts() {
        this.createStrengthChart();
        this.createCharacterChart();
    }

    createStrengthChart() {
        const ctx = document.getElementById('strengthChart');
        if (!ctx) {
            setTimeout(() => this.createStrengthChart(), 100);
            return;
        }
        
        if (this.charts.strength) {
            this.charts.strength.destroy();
        }
        
        this.charts.strength = new Chart(ctx, {
            type: 'line',
            data: {
                labels: [this.currentLanguage === 'en' ? 'Start' : 'Başlangıç'],
                datasets: [{
                    label: this.currentLanguage === 'en' ? 'Password Strength' : 'Şifre Gücü',
                    data: [0],
                    borderColor: '#667eea',
                    backgroundColor: 'rgba(102, 126, 234, 0.1)',
                    tension: 0.4,
                    fill: true,
                    borderWidth: 2
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        display: true,
                        position: 'top'
                    }
                },
                scales: {
                    y: {
                        beginAtZero: true,
                        max: 100,
                        title: {
                            display: true,
                            text: this.currentLanguage === 'en' ? 'Strength' : 'Güç'
                        },
                        grid: {
                            color: 'rgba(0,0,0,0.1)'
                        }
                    },
                    x: {
                        title: {
                            display: true,
                            text: this.currentLanguage === 'en' ? 'Tests' : 'Testler'
                        },
                        grid: {
                            color: 'rgba(0,0,0,0.1)'
                        }
                    }
                }
            }
        });
    }

    createCharacterChart() {
        const ctx = document.getElementById('characterChart');
        if (!ctx) {
            setTimeout(() => this.createCharacterChart(), 100);
            return;
        }
        
        if (this.charts.character) {
            this.charts.character.destroy();
        }
        
        this.charts.character = new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: this.currentLanguage === 'en' 
                    ? ['Uppercase', 'Lowercase', 'Numbers', 'Special']
                    : ['Büyük Harf', 'Küçük Harf', 'Rakamlar', 'Özel'],
                datasets: [{
                    data: [1, 1, 1, 1],
                    backgroundColor: ['#FF6B6B', '#4ECDC4', '#45B7D1', '#96CEB4'],
                    borderWidth: 2,
                    borderColor: '#fff'
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'bottom',
                        labels: {
                            padding: 15,
                            usePointStyle: true
                        }
                    }
                },
                cutout: '50%'
            }
        });
    }

    updateCharts(password) {
        if (!this.charts.strength || !this.charts.character) {
            setTimeout(() => this.updateCharts(password), 100);
            return;
        }
        
        this.updateStrengthChart();
        this.updateCharacterChart(password);
    }

    updateStrengthChart() {
        if (!this.charts.strength) return;
        
        const historyData = this.passwordHistory.slice(-5);
        const labels = historyData.map((_, index) => 
            `${this.currentLanguage === 'en' ? 'Test' : 'Test'} ${index + 1}`
        );
        const strengths = historyData.map(item => item.strength);
        
        if (strengths.length === 0) {
            strengths.push(0);
            labels.push(this.currentLanguage === 'en' ? 'Start' : 'Başlangıç');
        }
        
        this.charts.strength.data.labels = labels;
        this.charts.strength.data.datasets[0].data = strengths;
        this.charts.strength.update('none');
    }

    updateCharacterChart(password) {
        if (!this.charts.character) return;
        
        const upper = (password.match(/[A-Z]/g) || []).length;
        const lower = (password.match(/[a-z]/g) || []).length;
        const numbers = (password.match(/\d/g) || []).length;
        const special = (password.match(/[^A-Za-z0-9]/g) || []).length;
        
        const total = upper + lower + numbers + special;
        const data = total > 0 ? [upper, lower, numbers, special] : [1, 1, 1, 1];
        
        this.charts.character.data.datasets[0].data = data;
        this.charts.character.update('none');
    }

    exportPDF() {
        const strength = document.getElementById('strengthText').textContent;
        const health = document.getElementById('healthScore').textContent;
        
        const report = this.currentLanguage === 'en' 
            ? `PASSWORD ANALYSIS REPORT
========================
Strength: ${strength}
Health Score: ${health}/100
Generated: ${new Date().toLocaleString()}

🔒 Includes Have I Been Pwned breach data
📊 Advanced security analytics
🔄 Password comparison features
⚙️ Password Rule Engine

PDF export feature is ready!`
            : `ŞİFRE ANALİZ RAPORU
===================
Güç: ${strength}
Sağlık Skoru: ${health}/100
Oluşturulma: ${new Date().toLocaleString()}

🔒 Have I Been Pwned ihlal verisi içerir
📊 Gelişmiş güvenlik analitiği
🔄 Şifre karşılaştırma özellikleri
⚙️ Şifre Kuralı Motoru

PDF dışa aktarma özelliği hazır!`;
        
        alert(this.currentLanguage === 'en' ? 'PDF Export:\n' + report : 'PDF Dışa Aktarma:\n' + report);
    }

    exportCSV() {
        if (this.passwordHistory.length === 0) {
            alert(this.currentLanguage === 'en' ? 'No data to export!' : 'Dışa aktarılacak veri yok!');
            return;
        }
        
        const headers = this.currentLanguage === 'en' 
            ? 'Password,Strength,Entropy,Timestamp'
            : 'Şifre,Güç,Entropi,Zaman';
        
        const csvContent = this.passwordHistory.map(item => 
            `${item.password},${item.strength},${item.entropy},${item.timestamp}`
        ).join('\n');
        
        const blob = new Blob([`${headers}\n${csvContent}`], { type: 'text/csv' });
        const url = URL.createObjectURL(blob);
        
        const a = document.createElement('a');
        a.href = url;
        a.download = 'password_analysis.csv';
        a.click();
        
        URL.revokeObjectURL(url);
        alert(this.currentLanguage === 'en' ? 'CSV file downloaded!' : 'CSV dosyası indirildi!');
    }

    startBruteforceSimulation() {
        const password = document.getElementById('passwordInput').value;
        if (!password) {
            alert(this.currentLanguage === 'en' 
                ? 'Please enter a password first!' 
                : 'Lütfen önce bir şifre girin!');
            return;
        }

        this.runSimulation(password);
    }

    runSimulation(password) {
        const progressBar = document.getElementById('progressBar');
        const currentGuess = document.getElementById('currentGuess');
        const timeEstimate = document.getElementById('timeEstimate');
        const progressText = document.getElementById('progressText');
        
        progressBar.style.width = '0%';
        currentGuess.textContent = this.currentLanguage === 'en' ? 'Starting attack...' : 'Saldırı başlatılıyor...';
        if (timeEstimate) timeEstimate.textContent = '';
        if (progressText) progressText.textContent = '';

        let progress = 0;
        const interval = setInterval(() => {
            progress += 2;
            
            if (progress >= 100) {
                clearInterval(interval);
                progressBar.style.width = '100%';
                currentGuess.textContent = this.currentLanguage === 'en' 
                    ? `Password cracked: ${password}`
                    : `Şifre kırıldı: ${password}`;
                if (progressText) progressText.textContent = this.currentLanguage === 'en' ? '✅ Password found!' : '✅ Şifre bulundu!';
                return;
            }
            
            progressBar.style.width = `${progress}%`;
            
            const fakeGuess = this.generateRandomGuess(password.length);
            currentGuess.textContent = (this.currentLanguage === 'en' ? 'Trying: ' : 'Deneniyor: ') + fakeGuess;
            
            if (timeEstimate) {
                timeEstimate.textContent = (this.currentLanguage === 'en' ? 'Time remaining: ' : 'Kalan süre: ') + `${Math.round((100 - progress) * 50 / 100)}s`;
            }
            
            if (progressText) {
                progressText.textContent = (this.currentLanguage === 'en' ? 'Progress: ' : 'İlerleme: ') + `${progress}%`;
            }
            
        }, 100);
    }

    generateRandomGuess(length) {
        const chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%';
        let guess = '';
        for (let i = 0; i < length; i++) {
            guess += chars[Math.floor(Math.random() * chars.length)];
        }
        return guess;
    }

    generateStrongPassword() {
        const chars = {
            lower: 'abcdefghijklmnopqrstuvwxyz',
            upper: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
            numbers: '0123456789',
            symbols: '!@#$%^&*'
        };

        let password = '';
        
        password += chars.lower[Math.floor(Math.random() * chars.lower.length)];
        password += chars.upper[Math.floor(Math.random() * chars.upper.length)];
        password += chars.numbers[Math.floor(Math.random() * chars.numbers.length)];
        password += chars.symbols[Math.floor(Math.random() * chars.symbols.length)];

        const allChars = chars.lower + chars.upper + chars.numbers + chars.symbols;
        for (let i = password.length; i < 12; i++) {
            password += allChars[Math.floor(Math.random() * allChars.length)];
        }

        password = password.split('').sort(() => Math.random() - 0.5).join('');

        document.getElementById('generatedPassword').value = password;
        document.getElementById('passwordInput').value = password;
        this.analyzePassword(password);
    }

    copyToClipboard() {
        const passwordField = document.getElementById('generatedPassword');
        passwordField.select();
        document.execCommand('copy');
        
        if (this.currentLanguage === 'en') {
            alert('Password copied! 📋');
        } else {
            alert('Şifre kopyalandı! 📋');
        }
    }
}

let passwordAnalyzer;
document.addEventListener('DOMContentLoaded', () => {
    passwordAnalyzer = new PasswordAnalyzer();
});