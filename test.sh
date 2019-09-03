#!/bin/bash

echo "######################   setting the global workspace ##################################" 
GLOBAL_WORKSPACE="/home/lavoisier/svn_workspace/wapet/security"
FRIDADROID_FOLDER=$GLOBAL_WORKSPACE/fridaDroid
	# main working directory,  Inside, we should find (before running the command : bash test.sh apk_path)
	#  -------- the template of the frida gadget config file : libgadget.config.so_template
	#  -------- The gadget.so file 
	#  -------- the tracer project art-tracer-odile/_agent.js
	# It creates tmp files  to work  with 
	#  -------- the frida gadget config file for the app     : libgadget.config.so_for_pkg
	#  -------- the x86 tmp file 
	#  -------- the lib folder and lib.zip file
	#  -------- the intrumented apks inside the folder instrumented_apks_of_$pkg 
INSTRUMENTER_FOLDER=$GLOBAL_WORKSPACE/FridaInstrumenter_new_new/static
	#  The folder related to the Louison instrumentation tool contains
	#  -------- the template of the instrumenter config file main.json_template
        #  -------- the jar file of the instrumenter tool
	#  the tmp file is
        #  -------- the lib.zip file to add to the application.  

TRACER_JS=$FRIDADROID_FOLDER/art-tracer-odile/_agent.js
INSTRUMENTER_INPUT_FOLDER=$INSTRUMENTER_FOLDER/input_files
INSTRUMENTER_CONFIG_FILE=$INSTRUMENTER_FOLDER/main.json
INSTRUMENTER_JAR_FILE=$INSTRUMENTER_FOLDER/static-0.2.0.jar

echo "arg1 = $1"
if [ -z "$1" ] 
   then
	echo "No apk path supplied as argument "
: <<'END'
	echo "Ensure you have already started the emulator!!!"
	adb root
	echo "########################  lib.zip preparation ############################################"
	adb root
	rm -rf $FRIDADROID_FOLDER/x86/*
	cp  $FRIDADROID_FOLDER/libgadget.config.so $FRIDADROID_FOLDER/x86/libgadget.config.so
	cp $FRIDADROID_FOLDER/gadget.so $FRIDADROID_FOLDER/x86/libgadget.so
	rm $FRIDADROID_FOLDER/lib.zip $INSTRUMENTER_INPUT_FOLDER/lib.zip
	zip lib.zip x86 x86/*; 
	cp lib.zip $INSTRUMENTER_INPUT_FOLDER/
	echo  "#######################  instrumentation      ###########################################"
	INSTRUMENTER_OUTPUT_FOLDER=$FRIDADROID_FOLDER/instrumented
	rm -rfv $INSTRUMENTER_OUTPUT_FOLDER/*
	java -jar $INSTRUMENTER_JAR_FILE \
		       -c $INSTRUMENTER_CONFIG_FILE  \
		         -a $FRIDADROID_FOLDER/apks/test-frida-agent.apk 
	cp $INSTRUMENTER_OUTPUT_FOLDER/test-frida-agent-soot-frida-aligned-signed.apk .
	echo "########################  running the apk (The emulator need to be started) ###############"
	cp $INSTRUMENTER_OUTPUT_FOLDER/test-frida-agent-soot-frida-aligned-signed.apk .
	bash reinitialise_to_del.sh
	spd-say done;
END
else
        echo "testing apk $1"     
	echo "Ensure you have already started the emulator!!!"
	adb root
	echo "#########  lib.zip preparation ############################################"

	echo "########################  getting the name of the apk ####################################"
         
	pkg=$(aapt dump badging $1|awk -F" " '/package/ {print $2}'|awk -F"'" '/name=/ {print $2}')
	act=$(aapt dump badging $1|awk -F" " '/launchable-activity/ {print $2}'|awk -F"'" '/name=/ {print $2}')
	echo "package name : $pkg"
	echo "start activity name : $act"

	echo "########################  Config files modification ####################################"

	sed "s/package_name/$pkg/g" $FRIDADROID_FOLDER/libgadget.config.so_template > $FRIDADROID_FOLDER/libgadget.config.so_for_$pkg
	
	sed "s/instrumented_folder/instrumented_apks_of_$pkg/g" ${INSTRUMENTER_CONFIG_FILE}_template  > ${INSTRUMENTER_CONFIG_FILE}_for_${pkg}
	
        echo "########################  making the lib file ####################################"
	rm -rf $FRIDADROID_FOLDER/x86/*

	cp -v $FRIDADROID_FOLDER/libgadget.config.so_for_$pkg $FRIDADROID_FOLDER/x86/libgadget.config.so
	cp $FRIDADROID_FOLDER/gadget.so $FRIDADROID_FOLDER/x86/libgadget.so
        cp $TRACER_JS  $FRIDADROID_FOLDER/x86/libfridaDroidjs.so

	rm $FRIDADROID_FOLDER/lib.zip $INSTRUMENTER_INPUT_FOLDER/lib.zip
	zip lib.zip x86 x86/*; 
	cp lib.zip $INSTRUMENTER_INPUT_FOLDER/


	echo  "#######################  instrumentation      ###########################################"
	
	INSTRUMENTER_OUTPUT_FOLDER=$FRIDADROID_FOLDER/instrumented_apks_of_$pkg
	rm -rfv $INSTRUMENTER_OUTPUT_FOLDER
	mkdir $INSTRUMENTER_OUTPUT_FOLDER
	
	echo "the instrumented apks of this apk is $INSTRUMENTER_OUTPUT_FOLDER , \n the config file is ${INSTRUMENTER_CONFIG_FILE}_for_${pkg} "

	java -jar $INSTRUMENTER_JAR_FILE \
		       -c ${INSTRUMENTER_CONFIG_FILE}_for_${pkg}  \
		         -a $1

	echo "########################  running the apk (The emulator need to be started) ###############"

	adb uninstall $pkg
	repackagedApk="$(ls $INSTRUMENTER_OUTPUT_FOLDER)"
	adb install $INSTRUMENTER_OUTPUT_FOLDER/$repackagedApk
	adb shell am start -n $pkg/$act
	spd-say done;
fi

