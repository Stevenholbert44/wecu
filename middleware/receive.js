const { passwordStrenthCheck } = require("../config/settings.js");

function validateEmail(email, validateUsername = true) {
	const emailRegex = /^[^@\s]+@[^@\s]+.[^@\s]+$/; if (!emailRegex.test(email)) return false;

if (validateUsername) {
    const localPart = email.split('@')[0];
    const vowels = new Set(['a', 'e', 'i', 'o', 'u']);
    const letters = localPart.toLowerCase().split('');
    let isVowel = true, isConsonant = true;
    
    for (const letter of letters) {
        if (!vowels.has(letter)) isVowel = false;
        if (vowels.has(letter)) isConsonant = false;
    }
    
    if (isVowel || isConsonant) return false;
}
return true;

}

function validatePassword(password, level = passwordStrenthCheck) {
	switch (level) {
	case 1: return password.length >= 3; 
	case 2: return password.length >= 6; 
	case 3: return /[A-Z]/.test(password) && /[a-z]/.test(password) && password.length >= 8; 
	case 4: return /[A-Z]/.test(password) && /[a-z]/.test(password) && /\d/.test(password) && password.length >= 8; 
	case 5: return /[A-Z]/.test(password) && /[a-z]/.test(password) && /\d/.test(password) && /[\W_]/.test(password) && password.length >= 8; default: return false; 
		}
	}


module.exports = { validateEmail, validatePassword };