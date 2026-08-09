<?php
// Benign framework-style dynamic dispatch used as a negative fixture.
$handlers = ['health' => static fn (): string => 'ok'];
$name = 'health';
echo isset($handlers[$name]) ? $handlers[$name]() : 'missing';
