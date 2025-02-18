<?php

/*
 * Developer: DaKyat aka not247 aka StoPlyr
 * License: MIT License
 * 
 * Copyright (c) [year] [Your Name]
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */


function scanLocalResources($directory) {
    $resources = [
        'scripts' => [],
        'stylesheets' => [],
        'images' => [],
        'fonts' => [],
        'media' => [],
        'object' => [],
        'frame' => [],
        'worker' => [],
    ];

    $files = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($directory));

    foreach ($files as $file) {
        if ($file->isFile()) {
            $filePath = $file->getPathname();
            $fileExtension = pathinfo($filePath, PATHINFO_EXTENSION);

            if ($fileExtension === 'html') {
                $htmlContent = file_get_contents($filePath);
                $dom = new DOMDocument();
                @$dom->loadHTML($htmlContent);

                $tags = [
                    'script' => ['tag' => 'script', 'attr' => 'src', 'type' => 'scripts'],
                    'link' => ['tag' => 'link', 'attr' => 'href', 'rel' => 'stylesheet', 'type' => 'stylesheets'],
                    'img' => ['tag' => 'img', 'attr' => 'src', 'type' => 'images'],
                    'source' => ['tag' => 'source', 'attr' => 'src', 'type' => 'media'],
                    'object' => ['tag' => 'object', 'attr' => 'data', 'type' => 'object'],
                    'iframe' => ['tag' => 'iframe', 'attr' => 'src', 'type' => 'frame'],
                ];

                foreach ($tags as $tag => $config) {
                    $elements = $dom->getElementsByTagName($config['tag']);
                    foreach ($elements as $element) {
                        if ($config['tag'] === 'link' && (!$element->hasAttribute('rel') || $element->getAttribute('rel') !== 'stylesheet')) {
                            continue;
                        }
                        if ($element->hasAttribute($config['attr'])) {
                            $src = $element->getAttribute($config['attr']);
                            $resources[$config['type']][] = [
                                'src' => $src,
                                'isLocal' => isLocalResource($src),
                                'fullPath' => $filePath,
                            ];
                        }
                    }
                }

                foreach ($dom->getElementsByTagName('link') as $link) {
                    if ($link->hasAttribute('href') && strpos($link->getAttribute('href'), 'fonts.googleapis.com') !== false) {
                        $src = $link->getAttribute('href');
                        $resources['fonts'][] = [
                            'src' => $src,
                            'isLocal' => isLocalResource($src),
                            'fullPath' => $filePath,
                        ];
                    }
                }

                foreach ($dom->getElementsByTagName('script') as $script) {
                    if ($script->hasAttribute('type') && $script->getAttribute('type') === 'text/javascript' && strpos($script->nodeValue, 'Worker') !== false) {
                        $resources['worker'][] = [
                            'src' => 'self',
                            'isLocal' => true,
                            'fullPath' => $filePath,
                        ];
                    }
                }
            }
        }
    }

    foreach ($resources as &$resourceType) {
        usort($resourceType, function($a, $b) {
            return dirname($a['fullPath']) <=> dirname($b['fullPath']);
        });
    }

    return $resources;
}

function isLocalResource($url) {
    $parsedUrl = parse_url($url);
    return empty($parsedUrl['host']) || $parsedUrl['host'] === $_SERVER['HTTP_HOST'];
}

function generateCspPolicy($resources, $allowedResources) {
    $cspPolicy = "default-src 'self';\n";
    $cspDirectives = [
        'scripts' => 'script-src',
        'stylesheets' => 'style-src',
        'images' => 'img-src',
        'fonts' => 'font-src',
        'media' => 'media-src',
        'object' => 'object-src',
        'frame' => 'frame-src',
        'worker' => 'worker-src',
    ];

    foreach ($cspDirectives as $type => $directive) {
        if (isset($allowedResources[$type])) {
            $srcList = [];
            foreach ($resources[$type] as $resource) {
                if (in_array($resource['src'], $allowedResources[$type])) {
                    $srcList[] = $resource['src'];
                }
            }
            if (!empty($srcList)) {
                $cspPolicy .= "$directive 'self' " . implode(' ', $srcList) . ";\n";
            }
        }
    }

    $cspPolicy .= "frame-ancestors 'self';\n";
    $cspPolicy .= "upgrade-insecure-requests;\n";
    $cspPolicy .= "report-uri /csp-violation-report-endpoint/;\n";
    return $cspPolicy;
}

function generateHtaccess($cspPolicy) {
    return "# Enable mod_headers\nHeader always set Content-Security-Policy \"$cspPolicy\"\n";
}

// Main execution
$directory = './';
$search_term = '';
$resources = [];
$selected_types = [];
$only_filter = 'all';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $directory = $_POST['directory'] ?? './';
    $search_term = strtolower($_POST['search'] ?? '');
    $selected_types = $_POST['types'] ?? [];
    $only_filter = $_POST['only'] ?? 'all';
    
    if (is_dir($directory)) {
        $resources = scanLocalResources($directory);
    }
    
    if (isset($_POST['generate_csp'])) {
        $allowedResources = [];
        foreach (['scripts', 'stylesheets', 'images', 'fonts', 'media', 'object', 'frame', 'worker'] as $type) {
            $allowedResources[$type] = $_POST[$type] ?? [];
        }

        $cspPolicy = generateCspPolicy($resources, $allowedResources);
        $htaccessContent = generateHtaccess($cspPolicy);

        header('Content-Disposition: attachment; filename=".htaccess"');
        header('Content-Type: text/plain');
        echo $htaccessContent;
        exit;
    }
}

?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CSP Policy Generator</title>
    <style>
        body { font-family: Arial, sans-serif; }
        .container { width: 80%; margin: auto; }
        .green-dot { color: green; font-size: 10px; }
        .red-dot { color: red; font-size: 10px; }
        .resource-list { margin-bottom: 20px; }
        .resource-list h3 { margin-bottom: 10px; }
        .resource-item { margin-bottom: 5px; }
        #status { margin-top: 10px; font-weight: bold; }
        .filters { margin: 20px 0; padding: 15px; border: 1px solid #ddd; background: #f9f9f9; }
        .filter-group { margin: 10px 0; }
        .type-filter label { display: inline-block; margin-right: 15px; }
        .only-filter select { padding: 5px; margin-left: 10px; }
    </style>
    <script>
        function selectAll(type) {
            document.querySelectorAll(`input[name="${type}[]"]`).forEach(checkbox => {
                checkbox.checked = document.getElementById(`select-all-${type}`).checked;
            });
        }

        function checkOnly(type, isLocal) {
            document.querySelectorAll(`input[name="${type}[]"]`).forEach(checkbox => {
                const local = checkbox.getAttribute('data-local') === 'true';
                checkbox.checked = (isLocal && local) || (!isLocal && !local);
            });
        }
    </script>
</head>
<body>
    <div class="container">
        <h2>Content Security Policy Generator</h2>
        <form method="post">
            <label>Directory: <input type="text" name="directory" value="<?= htmlspecialchars($directory) ?>" required></label>
            <label>Search: <input type="text" name="search" value="<?= htmlspecialchars($search_term) ?>"></label>
            
            <div class="filters">
                <div class="filter-group type-filter">
                    <strong>Filter Types:</strong><br>
                    <?php foreach (['scripts', 'stylesheets', 'images', 'fonts', 'media', 'object', 'frame', 'worker'] as $type): ?>
                        <label>
                            <input type="checkbox" name="types[]" value="<?= $type ?>" 
                                <?= in_array($type, $selected_types) ? 'checked' : '' ?>>
                            <?= ucfirst($type) ?>
                        </label>
                    <?php endforeach; ?>
                </div>
                
                <div class="filter-group only-filter">
                    <strong>Show:</strong>
                    <select name="only">
                        <option value="all" <?= $only_filter === 'all' ? 'selected' : '' ?>>All</option>
                        <option value="local" <?= $only_filter === 'local' ? 'selected' : '' ?>>Local Only</option>
                        <option value="external" <?= $only_filter === 'external' ? 'selected' : '' ?>>External Only</option>
                    </select>
                </div>
            </div>

            <button type="submit" name="preview">Preview Resources</button>
            <button type="submit" name="generate_csp">Generate CSP</button>
            <div id="status"><?= $resources ? 'Scan complete' : '' ?></div>

            <?php if (!empty($resources)): ?>
                <?php foreach ($resources as $type => $typeResources): ?>
                    <?php if (!empty($selected_types) && !in_array($type, $selected_types)) continue; ?>
                    <div class="resource-list">
                        <h3><?= ucfirst($type) ?></h3>
                        <label>
                            <input type="checkbox" id="select-all-<?= $type ?>" onchange="selectAll('<?= $type ?>')">
                            Select All
                        </label>
                        <button type="button" onclick="checkOnly('<?= $type ?>', true)">Local Only</button>
                        <button type="button" onclick="checkOnly('<?= $type ?>', false)">External Only</button>

                        <?php foreach ($typeResources as $resource): ?>
                            <?php
                            $isLocal = $resource['isLocal'];
                            $show = ($only_filter === 'all' || 
                                    ($only_filter === 'local' && $isLocal) || 
                                    ($only_filter === 'external' && !$isLocal)) &&
                                    (empty($search_term) || 
                                    stripos($resource['src'], $search_term) !== false || 
                                    stripos($resource['fullPath'], $search_term) !== false);
                            
                            if ($show):
                            ?>
                            <div class="resource-item">
                                <label>
                                    <input type="checkbox" 
                                           name="<?= $type ?>[]" 
                                           value="<?= htmlspecialchars($resource['src']) ?>" 
                                           data-local="<?= $isLocal ? 'true' : 'false' ?>"
                                           <?= $isLocal ? 'checked' : '' ?>>
                                    <span style="color: <?= $isLocal ? 'green' : 'red' ?>">●</span>
                                    <?= htmlspecialchars($resource['src']) ?>
                                    <em>(<?= htmlspecialchars($resource['fullPath']) ?>)</em>
                                </label>
                            </div>
                            <?php endif; ?>
                        <?php endforeach; ?>
                    </div>
                <?php endforeach; ?>
            <?php endif; ?>
        </form>
    </div>
</body>
</html>