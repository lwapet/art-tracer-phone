'use strict';
import { trace } from "./tracer";
import { log } from "./logger";
log("!!!!!!!!!!!!!!!! it works on ARM!!!!!!!!!!!!!!!!!!!!");
setTimeout(() => {
    try {

        if(Process.arch == "ia32") {
            log("we are on ia32 bits");
            /*trace({
                onEnter(methodName) {
                    log("onEnter " + methodName);
                },
                onLeave(methodName) {
                }
            //});    
            },/.*write.**,/.**); */
        } else {
            trace({
                onEnter(methodName) {
                    log("onEnter " + methodName);
                },
                onLeave(methodName) {
                }
            //});  
            //},/android.app.ContextImpl/,/getPackageName/); 
            }/*,new RegExp (['android.app.ContextImpl',
            '|com.aegislab.sd3prj.antivirus.free.util.ae',
            '|com.aegislab.sd3prj.antivirus.free.service'].join('')),*/
            
            ,new RegExp (['com\.zoner\.android\.antivirus'].join('')),
          
            new RegExp (['.*'].join('')));

            //},/java.lang/,/.*/); 
            log(" !!!!!!!!! We are on another processor !!!!!!!!! " + Process.arch);
        }  
    } catch (error) {
        log("Oups --------> " + error.stack);
    }  
   
}, 1000);
