const fs = require('fs');
const vm = require('vm');
const path = require('path');  // To handle file paths

// Define the path to the data.js file
const dataJsPath = '/home/triagex/Downloads/ADAM/data.js';  // Replace with the actual path to data.js

// Define the output directory where JSON files will be saved
const outputDirectory = '/home/triagex/Downloads/ADAM/zircolite';  // Replace with your desired path

// Ensure the output directory exists
if (!fs.existsSync(outputDirectory)){
    fs.mkdirSync(outputDirectory, { recursive: true });
}

// Read the data.js file
const dataJsContent = fs.readFileSync(dataJsPath, 'utf8');

// Create a new VM context
const sandbox = {};
vm.createContext(sandbox);

// Evaluate the data.js content in the VM context
try {
    vm.runInContext(dataJsContent, sandbox);
} catch (error) {
    console.error('Error evaluating data.js:', error);
}

// List of variable names in data.js
const variables = [
    'ExecutionData',
    'HighData',
    'InitialAccessData',
    'PersistenceData',
    'PrivilegeEscalationData',
    'DefenseEvasionData',
    'CredentialAccessData',
    'DiscoveryData',
    'LateralMovementData',
    'CollectionData',
    'ExfiltrationData',
    'CommandAndControlData',
    'ImpactData',
    'OtherData',
    'UnknownData',
    'LowData',
    'MediumData',
    'CriticalData',
    'InformationalData'
];

// For each variable, write it to a JSON file in the specified output directory
variables.forEach(varName => {
    try {
        if (sandbox[varName]) {
            let varData = sandbox[varName];
            // If varData is a string, parse it as JSON
            if (typeof varData === 'string') {
                try {
                    varData = JSON.parse(varData);
                } catch (e) {
                    console.error(`Error parsing variable ${varName}: ${e.message}`);
                    return;  // Skip this variable if parsing fails
                }
            }
            const outputPath = path.join(outputDirectory, `${varName}.json`);
            fs.writeFileSync(outputPath, JSON.stringify(varData, null, 2));
            console.log(`Exported ${varName} to ${outputPath}`);
        } else {
            console.warn(`Variable ${varName} is not defined in data.js`);
        }
    } catch (error) {
        console.error(`Error exporting ${varName}:`, error.message);
    }
});

