<?php
// ============================================================================
// SETUP VERIFICATION SCRIPT
// ============================================================================
// This script checks if all files are properly configured

echo "Chat Application Setup Verification\n";
echo "=====================================\n\n";

$errors = [];
$warnings = [];
$success = [];

// Check 1: .env file exists
if (file_exists('.env')) {
    $success[] = "✓ .env file exists";
} else {
    $warnings[] = "⚠ .env file not found. Copy .env.example to .env and update it";
}

// Check 2: PHP version
if (version_compare(PHP_VERSION, '7.0.0', '>=')) {
    $success[] = "✓ PHP version " . PHP_VERSION . " is compatible";
} else {
    $errors[] = "✗ PHP 7.0+ required (currently " . PHP_VERSION . ")";
}

// Check 3: Required PHP extensions
$required_extensions = ['mysqli', 'json', 'filter'];
foreach ($required_extensions as $ext) {
    if (extension_loaded($ext)) {
        $success[] = "✓ PHP extension '$ext' is loaded";
    } else {
        $errors[] = "✗ Required PHP extension '$ext' is not loaded";
    }
}

// Check 4: File permissions
$upload_dir = __DIR__ . '/php/images';
if (is_dir($upload_dir)) {
    if (is_writable($upload_dir)) {
        $success[] = "✓ Upload directory is writable";
    } else {
        $warnings[] = "⚠ Upload directory exists but is not writable";
    }
} else {
    $warnings[] = "⚠ Upload directory does not exist. Creating...";
    mkdir($upload_dir, 0755, true);
}

// Check 5: Security files exist
$security_files = [
    'php/config.php',
    'php/security.php',
    'php/login.php',
    'php/signup.php',
    'php/search.php',
    'php/users.php',
    'php/data.php',
    'php/get-chat.php',
    'php/logout.php'
];

foreach ($security_files as $file) {
    if (file_exists($file)) {
        $success[] = "✓ Required file exists: $file";
    } else {
        $errors[] = "✗ Missing required file: $file";
    }
}

// Check 6: Verify no broken PHP syntax in critical files
$files_to_check = [
    'php/config.php',
    'php/security.php',
    'php/signup.php',
    'php/login.php'
];

foreach ($files_to_check as $file) {
    if (file_exists($file)) {
        $output = shell_exec("php -l " . escapeshellarg($file) . " 2>&1");
        if (strpos($output, 'No syntax errors') !== false) {
            $success[] = "✓ PHP syntax valid: $file";
        } else {
            $errors[] = "✗ Syntax error in $file: $output";
        }
    }
}

// Display results
echo "ERRORS:\n";
if (empty($errors)) {
    echo "  No errors found!\n\n";
} else {
    foreach ($errors as $error) {
        echo "  $error\n";
    }
    echo "\n";
}

echo "WARNINGS:\n";
if (empty($warnings)) {
    echo "  No warnings!\n\n";
} else {
    foreach ($warnings as $warning) {
        echo "  $warning\n";
    }
    echo "\n";
}

echo "SUCCESS:\n";
if (empty($success)) {
    echo "  No checks passed\n\n";
} else {
    foreach ($success as $s) {
        echo "  $s\n";
    }
    echo "\n";
}

// Summary
$total = count($errors) + count($warnings) + count($success);
echo "=====================================\n";
echo "Summary: " . count($success) . "/$total checks passed\n";

if (count($errors) === 0 && count($warnings) === 0) {
    echo "Status: ✓ READY FOR DEPLOYMENT\n";
} elseif (count($errors) === 0) {
    echo "Status: ⚠ WARNINGS - Review before deployment\n";
} else {
    echo "Status: ✗ ERRORS - Fix before deployment\n";
}

echo "=====================================\n";
?>
