#!/bin/bash

echo "================================================================================"
echo "appinspect version"
echo "================================================================================"
splunk-appinspect list version


splunk-appinspect list checks --custom-checks-dir Rules --included-tags rule1 --excluded-tags splunk-appinspect


echo "================================================================================"
echo "Run rules1"
echo "================================================================================"
splunk-appinspect inspect AppList/app-1   --custom-checks-dir Rules --included-tags rule1 --excluded-tags splunk-appinspect  --data-format json --output-file results.json