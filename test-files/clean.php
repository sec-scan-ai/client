<?php
// Simple clean PHP file
function greet(string $name): string {
    return "Hello, " . htmlspecialchars($name, ENT_QUOTES, 'UTF-8');
}

echo greet("World");
