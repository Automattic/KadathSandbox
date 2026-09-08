<?php
$o = get_option("x"); // MARK_AMBER
if ($o) { echo base64_decode($o); }
