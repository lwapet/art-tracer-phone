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
            },/.*write.*/,/.*/);
            log(" !!!!!!!!! We are on another processor !!!!!!!!! " + Process.arch);
        }  
    } catch (error) {
        log("Oups --------> " + error.stack);
    }  
   
}, 1000);
