// comments nomenclature
//  /* -- correct code -- */
//  // -- correct code 

import * as Java from "frida-java";
import { getApi } from "frida-java/lib/android";
import { getArtThreadFromEnv } from "frida-java/lib/android";
import { log } from "./logger";
import { test_client, send_log } from "./client_logger";
import  VM  from "frida-java/lib/vm"
import { prototype } from "stream";
import { print } from "util";
import { StdInstrumentationStackDeque, StdString, MethodInfoDecryptage, Stack } from "./tools";
import { threadId } from "worker_threads";
const api = getApi();


export interface TraceCallbacks {
    onEnter(methodName: string | null): void;
    onLeave(methodName: string | null): void;
}

enum InstrumentationEvent {
    MethodEntered = 0x1,
    MethodExited = 0x2,
    MethodUnwind = 0x4,
    DexPcMoved = 0x8,
    FieldRead = 0x10,
    FieldWritten = 0x20,
    ExceptionCaught = 0x40,
    Branch = 0x80,
    InvokeVirtualOrInterface = 0x100,
}

const retainedHandles: any[] = [];  // to keep calbacks alive

var in_odile: boolean = false // if true, we are with the Odile GUI APP
let attachCurrentThread_attached = 0;

let userTraceCallbacks: TraceCallbacks;

let listener: NativePointer;
try {
    listener = makeListener();
} catch (e) {
    log("Shit: " + e.stack);
}

//const runtime = api.artRuntime; //No longer used

let methodRegex: RegExp = /.*/;
let classRegex: RegExp = /.*/;
const dlopen = getDlopen();
const dlsym = getDlsym();
const artlib : any = dlopen("/system/lib64/libart.so");
add_to_log("*****artlib handler obtained !! " + artlib);
const libcpp : any = dlopen("/system/lib64/libc++.so");
add_to_log("*****libcpp handler obtained !! " + libcpp);
const libc : any = dlopen("/system/lib64/libc.so"); 
add_to_log("**** libc handler obtained !! " + libc);
add_to_log(" Computing the runtime address ");
const runtime : NativePointer = computeRuntimeObjectAddress(); // In aarch64 (samsung A7), I think the compilator has a different behaviour
                                          // and the runtime object is store at a static place dynamically defined at runtime
                                          // this place can be obained by looking some functions using the runtime object in libart source 
                                          // like Dbg::RequiresDeoptimization (mangled name _ZN3art3Dbg22RequiresDeoptimizationEv)
                                          // I take it dynamically in function computeRuntimeObjectAddress() see above
add_to_log("address computed " + runtime); 
let baseAddress : NativePointer;

//HELPER CODE , all commands related to it are commented with ///
///const helperPath = "/data/local/tmp/re.frida.server/libart-tracer-helper.so";
///const helper : any = dlopen(helperPath);
///add_to_log("**** libc helper obtained !! " + helper);
const method_Invoke: any = new NativeFunction(
    dlsym(artlib,"_ZN3art9ArtMethod6InvokeEPNS_6ThreadEPjjPNS_6JValueEPKc"),
    "void",
    ["pointer","pointer","uint32","pointer","pointer"],
    {
        exceptions: ExceptionsBehavior.Propagate
    });
add_to_log("**** Method invoke  !! " + method_Invoke);
let function_attached = 0;

const getNameAsString: any = new NativeFunction(
    dlsym(artlib,"_ZN3art9ArtMethod15GetNameAsStringEPNS_6ThreadE"),
    "pointer",
    ["pointer","pointer"],
    {
        exceptions: ExceptionsBehavior.Propagate
    }); 
const getUtfLength: any = new NativeFunction(
    dlsym(artlib,"_ZN3art6mirror6String12GetUtfLengthEv"),
    "int32",
    ["pointer"],
    {
        exceptions: ExceptionsBehavior.Propagate
    });
const toCharArray: any = new NativeFunction(
    dlsym(artlib,"_ZN3art6mirror6String11ToCharArrayEPNS_6ThreadE"),
    "pointer",
    ["pointer","pointer"],
    {
        exceptions: ExceptionsBehavior.Propagate
    });
const getData: any = new NativeFunction(
    dlsym(artlib ,"_ZNK3art6mirror14PrimitiveArrayItE7GetDataEv") ,
    "pointer",
    ["pointer"],
    {
        exceptions: ExceptionsBehavior.Propagate
    });
const getDescriptor: any = new NativeFunction(
    dlsym(artlib,"_ZN3art6mirror5Class13GetDescriptorEPNSt3__112basic_stringIcNS2_11char_traitsIcEENS2_9allocatorIcEEEE") as NativePointer,
    "pointer",
    ["pointer","pointer"],
    {
        exceptions: ExceptionsBehavior.Propagate
    });
add_to_log("retriving MethodEnterEventImpl");
const MethodEnterEventImpl: any = new NativeFunction(
    dlsym(artlib,"_ZNK3art15instrumentation15Instrumentation20MethodEnterEventImplEPNS_6ThreadEPNS_6mirror6ObjectEPNS_9ArtMethodEj") as NativePointer,
    "void",
    ["pointer","pointer","pointer","pointer","uint32"],
    {
        exceptions: ExceptionsBehavior.Propagate
    });
add_to_log("retriving ArtInterpreterToInterpreterBridge");
 const ArtInterpreterToInterpreterBridge: any = new NativeFunction( 
 dlsym(artlib,"_ZN3art11interpreter33ArtInterpreterToInterpreterBridgeEPNS_6ThreadEPKNS_7DexFile8CodeItemEPNS_11ShadowFrameEPNS_6JValueE"),
 "void",
 ["pointer", "pointer", "pointer", "pointer", "pointer"],
 {
     exceptions: ExceptionsBehavior.Propagate
 });  
let decryptageStack = new Stack<MethodInfoDecryptage> ();


 const declaringClassOffset = 0;


var log_bloc: string = "";
var number_of_block_send = 0;
var current_number_of_lines = 0; 

function add_to_log(string: String){
    if(string == "") return;
    if (!in_odile){
        log("standalone: " + string);
        return;
    }
    if (number_of_block_send > 30){
        log("frida tracer : Stopping sending blocks -******----");
        return;
    }
    if (current_number_of_lines >  100){
        send_log(log_bloc);
       
        current_number_of_lines = 0;
        number_of_block_send = number_of_block_send + 1;
        log("frida tracer: -----.-----.-----. BLOCK SENT: id : " + number_of_block_send + " content : \n" + log_bloc );
        log_bloc = "";
    } //else {
        log_bloc = log_bloc + string;
        current_number_of_lines++;
        //log(" adding new line " + current_number_of_lines);
    //}
}


    
export function trace(userTraceCallbacks_: TraceCallbacks, classRegex_: RegExp = /.*/, methodRegex_ : RegExp = /.*/) {
    methodRegex = methodRegex_;
    classRegex = classRegex_;
    userTraceCallbacks = userTraceCallbacks_;
    Java.perform(() => {
        add_to_log("****testing modification of inputs : getting offset of art_instrumentation object");
           /** Code used by the helper 
                const getOffsetOfRuntimeInstrumentation: any = new NativeFunction(dlsym(helper, "ath_get_offset_of_runtime_instrumentation"), "uint", []);
                let instrumentationOffset: any = getOffsetOfRuntimeInstrumentation();
                add_to_log("****instrumentation offset is  " + instrumentationOffset);  
           */
            /** SOME EXPLAINATIONS 
            When looking at the aarch64 asm code of some functions using the instrumentation object or calling for Runtime->getInstrumentation()
            I realized that other operations is being made like (from code Dgb::RequiresDeoptimization)
            ldr x21, [x21, 0x2e0]       ; [0x2e0:4]=-1 ; 736  (the actual pointer I should obtain If I just use the offset computed from my helper)
            ldr x20, [x21]               // A memory read at this address
            ldrb w10, [x20, 0x2dc]       // a memory read at the new address plus another offset, to have the forced_interpret_only_ element VALUE of 
                                        //the Instrumentation object in w10, it means the instrumentation object is at this address x20 + 0x2d8 = x2dc - 0x4; 728
                                        //the offset of forced_interpret_only_ returned by the helper and the one used in functions like
                                        //Instrumentation::MethodEnterEventImpl (using have_method_entry_listeners_ as offset 5) are the same
            */
       
        
        let asmInstrumentationCodeOffset_0x2d8 = 728; //728 because it is (the real offset the offset returned
                                                      //-8 because I considere the real library
      
        
        add_to_log("second line x20 =  " + runtime);
        const instrumentation = runtime.add(asmInstrumentationCodeOffset_0x2d8);
        add_to_log("third line: instrumentation address " + instrumentation);
        add_to_log("** memory dump of intrumentaion object " + hexdump(instrumentation, {
            offset: 0,
            length: 24,
            header: true,
            ansi: true
          }));
       
    
 


        add_to_log("test to del");
        //log("***** Now looking at the offset used in my assembly code ")
        //const testOffsetOfDeoptimizationEnabled : any = new NativeFunction(dlsym(helper, "ath_instrumentation_deoptimization_enabled_with_my_offset"), "bool", ["pointer"]);
        //log("address of my function " + testOffsetOfDeoptimizationEnabled);
        //log("**** My source code " ); printAsm(testOffsetOfDeoptimizationEnabled,100);
        //const DeoptimisationEnabled : any = new NativeFunction(dlsym(helper, "ath_instrumentation_deoptimization_enabled"), "bool", ["pointer"]);
        //log("**** firmware code " ); printAsm(DeoptimisationEnabled,100);

       

        // END HELPER CODE
        const addListener: any = new NativeFunction(
            dlsym(artlib,"_ZN3art15instrumentation15Instrumentation11AddListenerEPNS0_23InstrumentationListenerEj"),
            "void",
            ["pointer","pointer","uint32"],
            {
                exceptions: ExceptionsBehavior.Propagate
            });
        const enableDeoptimization: any = new NativeFunction(
            dlsym(artlib,"_ZN3art15instrumentation15Instrumentation20EnableDeoptimizationEv"),
            "void",
            ["pointer"],
            {
                exceptions: ExceptionsBehavior.Propagate
            });
        add_to_log("***address Of addListener " + addListener);    
        add_to_log("***address Of enableDeoptimization " + enableDeoptimization); 
        printAsm(enableDeoptimization, 20);   
        //_ZNK3art15instrumentation15Instrumentation15GetQuickCodeForEPNS_9ArtMethodENS_11PointerSizeE
        // const void* Instrumentation::GetQuickCodeFor(ArtMethod* method, PointerSize pointer_size) 
        add_to_log("before getQuickCodeFor");
        const getQuickCodeFor: any = new NativeFunction( 
            dlsym(artlib,"_ZNK3art15instrumentation15Instrumentation15GetQuickCodeForEPNS_9ArtMethodENS_11PointerSizeE"),
            "void",
            ["pointer", "pointer", "uint32"],
            {
                exceptions: ExceptionsBehavior.Propagate
            });
        add_to_log("***address Of getQuickCodeFor" + getQuickCodeFor); 
        printAsm(getQuickCodeFor, 100); 
 
        add_to_log("before CreateImtConflictMethod ");
        const CreateImtConflictMethod: any = new NativeFunction( 
        dlsym(artlib,"_ZN3art7Runtime23CreateImtConflictMethodEPNS_11LinearAllocE"),
        "pointer",
        ["pointer", "pointer"],
        {
            exceptions: ExceptionsBehavior.Propagate
        });  
        add_to_log("***address Of CreateImtConflictMethod" + CreateImtConflictMethod); 
        printAsm(CreateImtConflictMethod, 100); 



        add_to_log("before OutputMethodReturnValue ");
        const OutputMethodReturnValue: any = new NativeFunction( 
        dlsym(artlib,"_ZN3art3Dbg23OutputMethodReturnValueEmPKNS_6JValueEPNS_4JDWP9ExpandBufE"),
        "void",
        ["pointer", "uint32", "pointer", "pointer"],
        {
            exceptions: ExceptionsBehavior.Propagate
        });  
        add_to_log("***address Of OutputMethodReturnValue" + OutputMethodReturnValue); 
        printAsm(OutputMethodReturnValue, 100); 

        

        
        //extern "C" TwoWordReturn artQuickGenericJniTrampoline(Thread* self, ArtMethod** sp)
        //artQuickGenericJniTrampoline

        add_to_log("before artQuickGenericJniTrampoline ");
        const artQuickGenericJniTrampoline: any = new NativeFunction( 
        dlsym(artlib,"artQuickGenericJniTrampoline"),
        "pointer",
        ["pointer", "pointer"],
        {
            exceptions: ExceptionsBehavior.Propagate
        });  
        add_to_log("***address Of artQuickGenericJniTrampoline" + artQuickGenericJniTrampoline); 
        printAsm(artQuickGenericJniTrampoline, 100); 


        //todel  
        add_to_log("***address Of ArtInterpreterToInterpreterBridge" + ArtInterpreterToInterpreterBridge); 
        printAsm(ArtInterpreterToInterpreterBridge, 100); 
    

        let deoptimisation_enabled: number = Memory.readU8(instrumentation.add(344));
      
        printAsm(enableDeoptimization, 20);    

        add_to_log("before the call, deoptimisation_enable = " + deoptimisation_enabled);
        
        enableDeoptimization(instrumentation/*.add(200 * Process.pointerSize)*/);
        deoptimisation_enabled = Memory.readU8(instrumentation.add(344));
        add_to_log("after the call, deoptimisation_enable = " + deoptimisation_enabled);



     


        //log("address Of enableDeoptimization " + enableDeoptimization);
        add_to_log("retriving deoptimizeEverething address");
        const deoptimizeEverything: any = new NativeFunction(
        dlsym(artlib,"_ZN3art15instrumentation15Instrumentation20DeoptimizeEverythingEPKc"),
        "void",
        ["pointer","pointer"],
        {
            exceptions: ExceptionsBehavior.Propagate
        });
        log("address Of deoptimizeEverything " + deoptimizeEverything);

        if (baseAddress == null){
            let staticDeoptimizeEverythingAddress = 2425716;//address obtained statically with radare2 is 0x00250374 in decimal is 2425716
            baseAddress = deoptimizeEverything.sub(2425716);
            log ("======> Base address = " + baseAddress);
        }
        
        //todel
        if(!function_attached){
            //patchFunctionToBacktrace(method_Invoke); function_attached = 1;
            //patchFunctionToBacktrace(MethodEnterEventImpl); function_attached = 1;
            //patchMethodEnterEventImpl(); function_attached = 1;
            patchArtInterpreterToInterpreterBridge();
        }
        // to uncomment  */
        deoptimizeEverything(instrumentation, Memory.allocUtf8String("frida"));
        //add_to_log("before adding listener");
        addListener(instrumentation, listener, InstrumentationEvent.MethodEntered  );/* InstrumentationEvent.MethodEntered  | InstrumentationEvent.MethodExited | InstrumentationEvent.FieldRead | InstrumentationEvent.FieldWritten*/ //--);
        //add_to_log("after adding listener");


      
        //if(Process.arch == "ia32") log("----------end of trace function code"  +   Process.arch);
    }); 
}

function patchArtInterpreterToInterpreterBridge(): void{
    add_to_log("----------------------------> Patching ArtInterpreterToInterpreterBridge to obtain code item + shadow frame" );
    /*void ArtInterpreterToInterpreterBridge(Thread* self,
        const DexFile::CodeItem* code_item,
        ShadowFrame* shadow_frame,
        JValue* result)*/
    Interceptor.attach(ArtInterpreterToInterpreterBridge, {
        onEnter: function (args) {
            let thread = args[0];
            let code_item = args[1];
            let shadow_frame = args[2];
            
           
            // log("#####> called from: " + Thread.backtrace(context, Backtracer.ACCURATE)/*.map(DebugSymbol.fromAddress).join("\n\t#####>")*/);
            //Thread.sleep(0.5);
            //let backtrace = Thread.backtrace(mainThread_3.context, Backtracer.ACCURATE);
            let backtrace = Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join("\n\t#####>");
            //add_to_log("after backtrace");
            // GENERAL INFORMATIONS WE CAN OBTAIN IN ALL CASES, FOR NORMAL AND COMPILED METHODS  
            //add_to_log("" + hexdump(shadow_frame, {
            //    offset: 0,
            //    length: 24,
            //    header: true,
            //    ansi: true
            //  }));
            
            
            
            
            let method: NativePointer  = Memory.readPointer(shadow_frame.add(1 * Process.pointerSize));
            //add_to_log("shadow_frame = " + shadow_frame + " method = " + method + " Thread : " + thread + " code item " + code_item + " \n backtrace " + backtrace );
        
            let decryptageDatas: MethodInfoDecryptage = new MethodInfoDecryptage(code_item, shadow_frame);
          
            
            
           
           
            let methodNameStringObject = getNameAsString(method, thread); 
            const stringMethodName = getNameFromStringObject(methodNameStringObject, thread);

            let result_info: string = "";
            //result_info  = result_info + "\n ..... ..... ..... testing method name in the interceptor " + stringMethodName + " method regex " + methodRegex;
            if(!methodRegex.test(stringMethodName as string)){
                //result_info = result_info + "\n method name does not match";
                add_to_log(result_info);
                return;  
            }  
            /// GETTING THE CLASS NAME : APPROACH BY METHOD CLASS 
            const declaring_classHandle = method.add(declaringClassOffset);
            const declaring_class_ = ptr(Memory.readU32(declaring_classHandle));
            /// TRYING WITH THE DESCRIPTOR    const char* Class::GetDescriptor(std::string* storage)
            let rawClassName: string;
            const storage = new StdString();
            rawClassName = Memory.readUtf8String(getDescriptor(declaring_class_, storage)) as string;   
            storage.dispose();
            const className = rawClassName.substring(1, rawClassName.length - 1).replace(/\//g, ".");
            //result_info =  result_info + "\n testing class name " + className  + " class regex " + className;
            if(!classRegex.test(className)){
               //result_info =  result_info + "\n class name does not match";
               add_to_log(result_info);
               return;
            }
            result_info = result_info + " -----> IN THE ART_INTERPRETER_TO_INTERPRETER shadow frame memory\n " /* + hexdump(shadow_frame, {
                offset: 0,
                length: 24,
                header: true,
                ansi: true
              })*/;
            result_info  =  "\n shadow_frame = " + shadow_frame + " method = " + method + " Thread : " + thread + " code item " + code_item + " \n backtrace " + backtrace;
            result_info =  result_info + "\n  GOOD CANDIDATE!!!";
            result_info = result_info + "\n adding the decryptage data to the stack, stack size " +  decryptageStack.count;
            //add_to_log("adding the decryptage data to the stack, stack size" +  decryptageStack.count);
            decryptageStack.push(decryptageDatas);
            //MethodInfoDecryptageElement           
            //----->add_to_log(result_info);

        },
    });
    add_to_log("----------------------------> end patching " + NativeFunction.toString());
}
 
function patchMethodEnterEventImpl(): void{
    add_to_log("----------------------------> Patching MethodEnterEventImpl" );
    Interceptor.attach(MethodEnterEventImpl, {
        onEnter: function (args) {
            let thread = args[1];
            let thisObject = args[2];
            let method = args[3];
            
           
            // log("#####> called from: " + Thread.backtrace(context, Backtracer.ACCURATE)/*.map(DebugSymbol.fromAddress).join("\n\t#####>")*/);
            //Thread.sleep(0.5);
            //let backtrace = Thread.backtrace(mainThread_3.context, Backtracer.ACCURATE);
            let backtrace = Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join("\n\t#####>");
            
            // GENERAL INFORMATIONS WE CAN OBTAIN IN ALL CASES, FOR NORMAL AND COMPILED METHODS  
            let methodNameStringObject = getNameAsString(method, thread); 
            const stringMethodName = getNameFromStringObject(methodNameStringObject, thread);

            //add_to_log("testing method name" + stringMethodName + "regex " + methodRegex);
            /*if(!methodRegex.test(stringMethodName as string)){
                add_to_log("method name does not match");
                return;  
            }*/  
            /// GETTING THE CLASS NAME : APPROACH BY METHOD CLASS 
            const declaring_classHandle = method.add(declaringClassOffset);
            const declaring_class_ = ptr(Memory.readU32(declaring_classHandle));
            /// TRYING WITH THE DESCRIPTOR    const char* Class::GetDescriptor(std::string* storage)
            let rawClassName: string;
            const storage = new StdString();
            rawClassName = Memory.readUtf8String(getDescriptor(declaring_class_, storage)) as string;   
            storage.dispose();
            const className = rawClassName.substring(1, rawClassName.length - 1).replace(/\//g, ".");
            //add_to_log("testing class name");
            /*if(!classRegex.test(className)){
                add_to_log("class name does not match");
                return;
            }*/
            add_to_log("\n IN THE INTERCEPTOR -->  \n -------------------> pointer size " + Process.pointerSize + 
            " \n ----------------------------> OnEnter Of a Interceptor attached on MethodEnterEventImpl" + 
            " \n #####>before calling backtrace context " + JSON.stringify(this.context) +
            "\n thread = " + thread + ", \n --> thisObject= " + thisObject +
             ", \n method= " + method + ",\n descriptor=" + className + ",\n methodName=" + stringMethodName + 
            "#####> called from: " + backtrace);

            //TO GET THE SHORTY I NEED TO HAVE THE INTERFACE METHOD FIRST BY USING GetInterfaceMethodIfProxy()
            //IN THE ART SOURCE CODE, THIS METHOD CALLS Runtime::Current()->GetClassLinker()->FindMethodForProxy(this); AND RETURN THE RESULT 
            // AND BECAUSE THE LATEST IS EXPOSED, I WILL START BY IMPLEMENTING IT, I DONT USE THE CACHE AS IN THE GetInterfaceMethodIfProxy() 
            
            //let class_linker: NativePointer = Memory.readPointer(runtime.add(classLinker_offset));  
            //log("classLinker : " + class_linker);
            //let interfaceMethod = findMethodForProxy(class_linker, method);
            //log("Interface Method obtained" + interfaceMethod);


        },
    });
    add_to_log("----------------------------> end patching " + NativeFunction.toString());
}

function patchFunctionToBacktrace(native_function: NativeFunction): void{
    add_to_log("----------------------------> Patching " + NativeFunction.toString());
    Interceptor.attach(native_function, {
        onEnter: function (args) {
            this.thread = args[1];
            this.args = args[2];
            add_to_log("--------------------> pointer size " + Process.pointerSize);
            add_to_log("----------------------------> OnEnter Of a Interceptor attached on " + NativeFunction.toString());
            add_to_log("#####>before calling backtrace context " + JSON.stringify(this.context));
            // log("#####> called from: " + Thread.backtrace(context, Backtracer.ACCURATE)/*.map(DebugSymbol.fromAddress).join("\n\t#####>")*/);
            //Thread.sleep(0.5);
            //let backtrace = Thread.backtrace(mainThread_3.context, Backtracer.ACCURATE);
            let backtrace = Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join("\n\t#####>");
            add_to_log("#####> called from: " + backtrace);
            
        },
    });
    add_to_log("----------------------------> end patching " + NativeFunction.toString());
    /* will not work because this thread is not the app one 
    let threads =  Process.enumerateThreadsSync();
    let mainThread = threads[0];
    
    add_to_log('current Thread -- :' + Process.getCurrentThreadId() + " mainThread " + mainThread.id);
    add_to_log("runtime env " + Script.runtime);
    add_to_log("----------------------------> Patching invoke using stalker");
    threads.forEach(function (thread) {
        add_to_log(" adding callprobe on thread " + thread.id);
        var my_callprobe = Stalker.addCallProbe(native_function, function(args: any){
            add_to_log('------------------- In the stalker callback in thread js' + thread);
        });
    });
  
 
    add_to_log('Current thread :' + Process.getCurrentThreadId());
    Process.enumerateThreads({
        onMatch: function(t) {
            if(t.id == mainThread.id){
                add_to_log('following thread :' + t.id);
                Stalker.follow(t.id, {
                    events:{
                        call:true
                    }
                });
                add_to_log('following thread :' + Process.getCurrentThreadId());
                Stalker.follow(Process.getCurrentThreadId(), {
                    events:{
                        call:true
                    }
                });
            } else {
                add_to_log('ollowing threadf :' + t.id);
                try{
                    Stalker.follow(t.id, {
                        events:{
                            call:true
                        }
                    });
                } catch (error) {
                        log("Error shorty!");
                    }
                }      
        },
        onComplete: function(){
            add_to_log('Completed');
        }
    });
    add_to_log("----------------------------> Invoke Patched using stalker");
    */
   
    /*add_to_log("----------------------------> Patching invoke using Stalker");
    var callprobe_id = Stalker.addCallProbe(native_function, function(args: any){
        console.log('----------------------------> In the method stalker ');
    });
    add_to_log("----------------------------> Invoke Patched using stalker");*/

}

function makeListener(): NativePointer {
    const numVirtuals = 11;

    const listener = Memory.alloc(Process.pointerSize);
    retainedHandles.push(listener);

    const vtable = Memory.alloc(numVirtuals * Process.pointerSize);
    retainedHandles.push(vtable);
    Memory.writePointer(listener, vtable);
    for (let i = 0; i !== numVirtuals; i++) {
        switch(i) { 
            case 2: { 
                const method = makeMethodEntered();
                Memory.writePointer(vtable.add(i * Process.pointerSize), method);
                break; 
            } 
            case 3: { 
                const method = makeMethodExited();
                Memory.writePointer(vtable.add(i * Process.pointerSize), method);
                break; 
            } 
            case 6: { 
                const method = makeFieldRead();
                Memory.writePointer(vtable.add(i * Process.pointerSize), method);
                break; 
            } 
            case 7: { 
                const method = makeFieldWritten();
                Memory.writePointer(vtable.add(i * Process.pointerSize), method);
                break; 
            }
            default: { 
                const method = makeListenerMethod("vmethod" + i);
                Memory.writePointer(vtable.add(i * Process.pointerSize), method);
                break; 
            } 
        } 
    }
    return listener;
}

function getNameFromStringObject(stringObject:NativePointer, thread: NativePointer):string|null{
    let length = getUtfLength(stringObject);
    let charArray = toCharArray(stringObject,thread);
    let datas = getData(charArray);     
    return Memory.readUtf16String(datas,length);
} 

function makeMethodEntered(): NativePointer {
    
    const callback = new NativeCallback((self: NativePointer, thread: NativePointer, thisObject: NativePointer, 
                                                                                    method: NativePointer, dexPc: number): void => {
                                                                                       
        
        // GETTING THE CURRENT THREAD
        /*let threads =  Process.enumerateThreadsSync();
        let mainThread = threads[0] ;
        let current_thread_id = Process.getCurrentThreadId();
        add_to_log(" ****Current thread = " + current_thread_id);
        threads.forEach(function (thread) {
            add_to_log("------>testing the thread " + thread.id + " current thread " + current_thread_id);
            if(current_thread_id == thread.id){
                add_to_log("------>this thread is correct !! " + thread.id);
                mainThread =  thread;
            }
        });
        Process.enumerateThreads({
            onMatch: function(thread){
                add_to_log("enumerating the thread : " + thread.id);
                if(current_thread_id == thread.id){
                    add_to_log("------>this thread is correct !! " + thread.id);
                    mainThread =  thread;
                }
            },
            onComplete: function(){
                console.log('Done');
            }
        });*/
        
        
        /*add_to_log("----> mainthread id " + mainThread.id);
        let context = mainThread.context;*/
        //log("MethodEntered()  from the Interceptor ---method=" + this.method + " context=" + JSON.stringify(this.context));
        /*let current_sp = context.sp; 
        let current_pc = context.pc;*/
        let stack_offset_counter = 0;
        let dword_size = 4;
        let dex_pc_offset = 28; //(7*Process.PointerSize)
        let dex_pc_ptr_offset = 12; //(3*Process.pointerSize)
        let code_item_offset = 16;
        let classLinker_offset = 464; //0x1d0 from line 7 of runtime::CreateImtConflictMethod

        // GENERAL INFORMATIONS WE CAN OBTAIN IN ALL CASES, FOR NORMAL AND COMPILED METHODS  
        let methodNameStringObject = getNameAsString(method, thread); 
        const stringMethodName = getNameFromStringObject(methodNameStringObject,thread);

        let result_info: string =  "";
        result_info =  result_info + "\n ..... ..... ..... testing method name in listener " + stringMethodName + ", method regex " + methodRegex;
        if(!methodRegex.test(stringMethodName as string)){
            //add_to_log(result_info + result_info + "\n method name does not match");
            return;  
        }  
        /// GETTING THE CLASS NAME : APPROACH BY METHOD CLASS 
        const declaring_classHandle= method.add(declaringClassOffset);
        const declaring_class_ = ptr(Memory.readU32(declaring_classHandle));
        /// TRYING WITH THE DESCRIPTOR    const char* Class::GetDescriptor(std::string* storage)
        let rawClassName: string;
        const storage = new StdString();
        rawClassName = Memory.readUtf8String(getDescriptor(declaring_class_, storage)) as string;   
        storage.dispose();
        const className = rawClassName.substring(1, rawClassName.length - 1).replace(/\//g, ".");
        result_info =  result_info + "\n" + " testing class name " + className + ", ClassRegex " + classRegex;
        if(!classRegex.test(className)){
            //add_to_log(result_info + " \n class name does not match");
            return;
        }
        

        //GETTING THE SHORTY
        let return_type_string: any;
        //TO GET THE SHORTY I NEED TO HAVE THE INTERFACE METHOD FIRST BY USING  GetInterfaceMethodIfProxy()
        //IN THE ART SOURCE CODE, THIS METHOD CALLS Runtime::Current()->GetClassLinker()->FindMethodForProxy(this); AND RETURN THE RESULT 
        // AND BECAUSE THE LATEST IS EXPOSED, I WILL START BY IMPLEMENTING IT, I DONT USE THE CACHE AS IN THE GetInterfaceMethodIfProxy() 
        //let class_linker: NativePointer = Memory.readPointer(runtime.add(classLinker_offset));  
        //log("classLinker : " + class_linker);
        //let interfaceMethod = findMethodForProxy(class_linker, method);
        //FINALLY, BECAUSE findMethodForProxy IS NOT EXPOSED, I WILL CONSIDER THAT THIS METHOD IS ALREADY A NOT PROXY METHOD
        //ie WITH THE CURRENT METHOD THE CALL TO GetInterfaceMethodIfProxy  SHOULD RETURN this.  

         // NOW GETTING THE SHORTY FROM THE INTERFACE METHOD (method_index means index in the corresponding method_ids in the dex_file)(and the methood_id is the index in string_ids)
         // I reversed the function 
         let declaringClass: NativePointer = new NativePointer(Memory.readS32(method)); //same as x86, just the registry size to consider because it is too large
         //log ("Declaring class = " + declaringClass);
         let dexCache: NativePointer = new NativePointer(Memory.readS32(declaringClass.add(16))); // same as x86
         //log ("Dexcache = " + dexCache);
         let dexfile: NativePointer = Memory.readPointer(dexCache.add(16)); //same as x86--------- we use pointer (8 bytes on arm because in the asm it is code on a 8 byte register x8)
         //log("dexFile " + dexfile + "testing dexfile size " + Memory.readU32(dexfile.add(16)));
         let dex_method_index: number = Memory.readU32(method.add(12)); // different from x86 because of pointer size 
         //log("dex_method_index  " + dex_method_index);
         let method_ids: NativePointer =  Memory.readPointer(dexfile.add(96)); // 0x60-------- for the same reason as above (dw)
         //log("method_ids array" + method_ids);
         let proto_ids: NativePointer =  Memory.readPointer(dexfile.add(104));  // 0x68------ for the same reason as above (dw)
         //log("proto_ids array: " + proto_ids);



         let method_id: NativePointer = method_ids.add(dex_method_index * 8); // ---- for the same reason as above (dw)
         //log("method id " + method_id);
         let proto_idx: number = Memory.readU16(method_id.add(2)); // 
         //log("proto index " + proto_idx);
         
         let proto_id: NativePointer = proto_ids.add(proto_idx * 12);  /// can be used to obtain the return type
         //log("proto_id address  " + proto_id);
         let shorty_idx =  Memory.readU32(proto_id); // ----------- it is loaded in a word register
         //log("shorty_idx   " + shorty_idx);


         let string_ids: NativePointer = Memory.readPointer(dexfile.add(72)); // 0x48
         //log("string_ids array " + string_ids);
         let dex_file_begin: NativePointer = Memory.readPointer(dexfile.add(8));  //
         //log("dex_file_begin " + dex_file_begin);
         let prototype_string_offset: number = Memory.readU32(string_ids.add(shorty_idx * 4)); // 
         //log("prototype_string offsett old " + prototype_string_offset);
         if(Memory.readPointer(dex_file_begin.add(prototype_string_offset)).equals(NULL)) log("****error in getting the shorty"); 
         let prototype_string_address: NativePointer = dex_file_begin.add(prototype_string_offset + 1);
         //log("prototype_string_address : " + prototype_string_address);
         let shorty: any =  Memory.readUtf8String(prototype_string_address);
         //add_to_log(" shorty = " + shorty);
/*
......... mov x23, x1   ----------------------------x23 = art_method_add
......... ldr x8, [x9]  --------------------------- x8 = runtime_object (see function retriving_rutime_object())-------dw
......... ldr x20, [x23] -------------------------- x20 = callee (in the source code, it is the current method object)
......... ldr w8, [x20]---------------------------- w8 = method->declaring_class---w
......... ldr w0, [x8, #0x10]---------------------- w0 = x8->dexcache = method-> declaring_class -> dexcache-------w
......... ldr x8, [x0, #0x10] --------------------- x8 = x0-> dexfile = w0->dexfile =  method-> declaring_class -> dexcache-> dexfile------dw
......... ldr w9, [x20, #0xc] --------------------- w9 = x20->dex_method_index = callee->dex_method_index-----
......... ldp x10, x11, [x8, #0x60]---------------- x10 = dexfile->method_ids ; ----- x11 = dexfile->proto_ids
......... add x9, x10, x9, lsl #3 ----------------- x9 = x10 + 8 * x9 = method_ids  + 8 * dex_method_index = method_id
......... ldrh w9, [x9, #2] ----------------------- w9 = x9->proto_idx = method_id->proto_idx
......... orr w10, wzr, #0xc ---------------------- w10  = 12
......... mul x9, x9, x10 ------------------------- x9 = x10 * x9 = 12 * x9 = 12 * proto_idx
......... ldr w9, [x11, x9] ----------------------- w9 = content of (x11 + x9) = content of ( Protoids + 12 *  proto_idx )  = content of (proto_id) = shtoryidx (it is the first element)
......... ldr x10, [x8, #0x48]--------------------- x10 = x8->srtring_ids = dexfile -> string_ids 
......... ldr x8, [x8, #8]------------------------- x8 = x8->dexfile_begin = dexfile_begin_address
......... ldr w9, [x10, x9, lsl #2]---------------- w9 = content of (x10 + x9 * 4) = content of( string_ids + shtoryidx * 4)  = content_of (shorty_id) = proto_string_offset
......... add x8, x8, x9 -------------------------- x8 = x8 + x9 = x8 + W9 = dexfile_begin + proto_offset = proto_absolute_offset
......... mov x21, x8  ---------------------------- x21 = proto_absolute_offset
......... ldrsb w9, [x21], #1 -------------------- w9 = first_char_of_the_prototype....... 
......... and w25, w9, #0xff
*/
        let number_inputs_from_method_object = 0;
        let type_ids =  Memory.readPointer(dexfile.add(80)); //0x50
        result_info = result_info + 
        "\n IN THE LISTENER --> param 0 =" + self +" thread = " + thread + ", \n --> thisObject= " + thisObject + 
        ", \n method= " + method + ",\n descriptor=" + className + ",\n methodName=" + stringMethodName 
        + " shorty = " + shorty + " \n " ;
        if(shorty.length == 1){
            result_info = result_info + " shorty length is one ";
            //log("need only to obtain the return type");
            if(shorty != "L"){
                return_type_string = getPrimitiveTypeAsString(shorty);
            }else{
                let return_type_idx: number =  Memory.readU16(proto_id.add(4));
                return_type_string = getStringByTypeIndex(type_ids, return_type_idx, string_ids, dex_file_begin);
                //add_to_log("Return type in string " + return_type_string);
                result_info = result_info + "\n  Return type in string " + return_type_string;
            }   
            //break;
        }else{
            //add_to_log(" shorty length is more than one ");
            // Obtaining the parameter list 
            result_info = result_info + "\n shorty length is more than one ";
            let param_type_list: NativePointer = getProtoParameters(proto_id, dex_file_begin);
            //log(" address of the param type list " + param_type_list + " size " + Memory.readS32(param_type_list));
            result_info = result_info + "\n address of the param type list " + param_type_list + " size " + Memory.readS32(param_type_list);
            let size =  Memory.readS32(param_type_list);
            let param_type_list_elt = param_type_list.add(4);
            
            number_inputs_from_method_object = size;
            for(let i = 0; i < size; i++) {
                let typeItem: NativePointer = param_type_list_elt.add(i * 2);//because 2 bytes is the size of one element 
                let type_idx: number = Memory.readU16(typeItem);
                let descriptor_string = getStringByTypeIndex(type_ids, type_idx, string_ids, dex_file_begin);
                result_info = result_info + "\n parameter_" + i + " type in string " + descriptor_string;
                //add_to_log("parameter" + i + "type in string " + descriptor_string);

            }
            let return_type_idx: number =  Memory.readU16(proto_id.add(4));
            return_type_string = getStringByTypeIndex(type_ids, return_type_idx, string_ids, dex_file_begin);
            result_info = result_info + " \n Return type in string " + return_type_string;
            //add_to_log("Return type in string " + return_type_string);


        }  


        //add_to_log(" getting the code item and the shadow frame ");
        let decrytage_info: MethodInfoDecryptage | null = decryptageStack.pop() as MethodInfoDecryptage; 
        let prospective_method = Memory.readPointer(decrytage_info.shadow_frame.add(1 * Process.pointerSize));
        //add_to_log(" prospective method " + prospective_method);
        if(prospective_method.compare(method) == 0){
            result_info = result_info + "\n ######## hey! shadow frame = " + decrytage_info.shadow_frame + " \n code_item = " + decrytage_info.code_item;
            //add_to_log(" ######## hey! shadow frame = " + decrytage_info.shadow_frame + " \n code_item = " + decrytage_info.code_item); 
        }else{
            result_info = result_info + "\n ERROR : cannot get the shadow frame";
            add_to_log (result_info);
            //decryptageStack.push(decrytage_info);
            return;

        }
        let shadow_frame: NativePointer = decrytage_info.shadow_frame;
        let code_item: NativePointer = decrytage_info.code_item;
        //log("Shadow frame code_item = " + prospective_shadow_frame_code_item);
        let number_registers = Memory.readU16(code_item);
        let number_inputs = Memory.readU16(code_item.add(2));
        //log("number of registers = " + number_registers + " number of inputs " + number_inputs);
        if(number_inputs <= number_registers){
            /// GETTING THE CALLER NAME AND HIS ClASS NAME TO TEST..
            // by direclyty looking inside the shadow frame, the caller is not avalaible see the code in the draft. 
            // so I decided to look at the stack (second time)
            // there are two cases in the interpreter; 
            ///   1--- If we where already in the interpreter and we have been called by 
            ///        docallCommon->PerformCall->ArtInterpreterToInterpreterBridge()
            ///         this is an easy option to retrive the caller because it in the caller shadow frame, third parameter of the former function (performCall is inlined)
            ///          the firsts parameters are thread and method (so adjacent on the stack,method is at k, and thread at k+1)
            ///  2---- If we where not in the interpreter, we are jumping in it 
            //            art_quick_to_interpreter_bridge->artQuickToInterpreterBridge->EnterInterpreterFromEntryPoint
            //              but little complicated because not sure  if  the sp contains the caller. 
            //  In the compile code (the second loop) The call is emulated when invoke_stub is called so the caller is null. 
            //firstly I print the stack. 
            ///  When looking at the stack the caller method in the case one is used when  the method is compiled PerformCall->artInterpreterToCompile. 
            /// And as described in the paper, it is null. 
            //scanMemory(thread_stack_pointer, 512);
            //log(" method executions stack: " + Thread.backtrace(this.context).map(DebugSymbol.fromAddress).join("\n\t"));
            
            


            let arg_offset: number = number_registers - number_inputs;
            let number_vregs: number = Memory.readU32(shadow_frame.add(48)); 
            
            let shadow_frame_vregs_: NativePointer = (shadow_frame.add(60));
            let args: NativePointer = shadow_frame_vregs_.add(arg_offset * 4); //uint32_t vregs_[0];
            let args_size: number = number_vregs - arg_offset; 
            result_info = result_info + "\n number of vreg " + number_vregs + ", number registers " + number_registers + 
            "\n ----> args pointer = " + args + "\n-----> size = " + args_size + 
            "\n -----> number inputs " + number_inputs + " \n memory at args pointer \n" + hexdump(args, {
                offset: 0,
                length: number_inputs * Process.pointerSize,
                header: true,
                ansi: true
              });
            

            //NOW DECRYPING ARGUMENTS, BASED ON THE LAST PART OF FUNCTION DoCallCommon
            //testing if the method is not static
            let current_offset_on_args: NativePointer = args;
            let access_flag: NativePointer = new NativePointer(Memory.readU32(method.add(4)));
            let is_static: number = access_flag.shr(32+24+4).shr(32+24+4+3).toInt32();
            result_info = result_info + "\n########### DECRYPTING ARGUMENTS: ";
            if(is_static){
                result_info = result_info + " \n the method is static";
            }else{
                result_info = result_info + "\n the method is not static and we process to offset inc on the vreg";
                current_offset_on_args = args.add(4);
            }
            let position_in_shorty = 0;
            while (position_in_shorty < number_inputs && position_in_shorty < number_inputs_from_method_object){
                let alpha_todel = position_in_shorty + 1; result_info = result_info + "\n processing the shorty at position: " + alpha_todel;
                if(shorty.charAt(position_in_shorty+1) == "L"){
                    // the first reference is a object, we read 32bits in the address of agrs
                    let ref: NativePointer = new NativePointer(Memory.readU32(current_offset_on_args));
                    result_info = result_info + " \n parameter: " + position_in_shorty + " object reference : " + ref;
                }else if(shorty.charAt(position_in_shorty+1) == "J") {//for long
                    result_info = result_info + " \n First attempt to read the value";
                    let value: UInt64 = Memory.readU64(current_offset_on_args);
                    result_info = result_info + "\n parameter " + position_in_shorty + " long value " + value ;
                    result_info = result_info + "\n second attempt to read the value as in the code source";
                    let value_at_args_offset_plus_1: NativePointer = new NativePointer(Memory.readU32(current_offset_on_args.add(4)));
                    let value_at_args_offset: NativePointer = new NativePointer(Memory.readU32(current_offset_on_args));
                    let final_value: NativePointer = value_at_args_offset_plus_1.shl(32).or(value_at_args_offset);
                    result_info = result_info + "\n value_at_args_offset_plus_1: " + value_at_args_offset_plus_1 + 
                    " value_at_args_offset: " + value_at_args_offset + 
                    " \n parameter " + position_in_shorty + " Long value " + final_value;
                    current_offset_on_args  = current_offset_on_args.add(4);
                }else if(shorty.charAt(position_in_shorty+1) == "D") {//for long
                    let value: number = Memory.readDouble(current_offset_on_args);
                    result_info = result_info + "\n parameter " + position_in_shorty + " double value " + value ;
                    current_offset_on_args  = current_offset_on_args.add(4);
                }else if(shorty.charAt(position_in_shorty + 1) == "B") {//for long
                    let value: number = Memory.readU8(current_offset_on_args);
                    result_info = result_info + "\n parameter " + position_in_shorty + " Byte value " + value ;
                }else if(shorty.charAt(position_in_shorty + 1) == "C"){
                    let value: string | null = Memory.readUtf8String(current_offset_on_args,1);
                    result_info = result_info + "\n parameter " + position_in_shorty + " Char value " + value ;
                }else if(shorty.charAt(position_in_shorty + 1) == "D"){
                    let value: number = Memory.readDouble(current_offset_on_args);
                    result_info = result_info + "\n parameter " + position_in_shorty + " Float value " + value ;
                }else if(shorty.charAt(position_in_shorty + 1) == "I"){
                    let value: number = Memory.readInt(current_offset_on_args);
                    result_info = result_info + "\n parameter " + position_in_shorty + " Integer value " + value ;   
                }else if(shorty.charAt(position_in_shorty + 1) == "S"){
                    let value: number = Memory.readShort(current_offset_on_args);
                    result_info = result_info + "\n parameter " + position_in_shorty + " Short value " + value ;   
                }else if(shorty.charAt(position_in_shorty + 1) == "Z"){
                    let value: boolean = Memory.readInt(current_offset_on_args) ? true : false; 
                    result_info = result_info + "\n parameter " + position_in_shorty + " Boolean value " + value ;   
                }else if(shorty.charAt(position_in_shorty + 1) == "V"){
                    let value: number = Memory.readU32(current_offset_on_args); 
                    result_info = result_info + "\n parameter " + position_in_shorty + " Void value " + value ;   
                }
                

                current_offset_on_args  = current_offset_on_args.add(4);
                position_in_shorty++;
            }

            //let result_register = Memory.readPointer(thread_stack_pointer.add(3*dword_size)); //because the biggest size of Jvalue is 4+4 bytes =2 * dword
            //log("Result register  = " + result_register);
            //let stay_in_interpreter = Memory.readInt(thread_stack_pointer.add(5*dword_size)); //because the biggest size of Jvalue is 4+4 bytes =2 * dword
            //log("stay in interpreter = " + stay_in_interpreter);
            add_to_log(result_info);
        }else {
            result_info = result_info + " \n ERROR : bad argument number ";
            add_to_log(result_info);
            return;
        }

        //log("Interface Method obtained" + interfaceMethod);
        //backtrace
        //Thread.sleep(0.5);
        //backtrace("listener", context);
        //log("#####> called from: " + Thread.backtrace(context, Backtracer.ACCURATE)/*.map(DebugSymbol.fromAddress).join("\n\t#####>")*/);

        
        //const mainThread = Process.enumerateThreads()[0];
        //just test the method
        // NOW GETTING THE ARGUMENTS
        // there is one of the possibles listener call graph when the method is called
        //art_quick_to_interpreter_bridge
        //              |
        //              v
        //artQuickToInterpreterBridge
        //              |
        //              v
        //interpreter::EnterInterpreterFromDeoptimize(self, deopt_frame, from_code, &result)
        //              |
        //              v
        //Execute(self, code_item, *shadow_frame, value)
        //              |
        //              v
        //instrumentation->MethodEnterEvent(self, shadow_frame.GetThisObject(code_item->ins_size_),method, 0);
        //              |
        //              v
        //MethodEnterEventImpl(thread, this_object, method, dex_pc)
        //              |
        //              v
        //listener->MethodEntered(thread, thiz, method, dex_pc);     
                                                                                                                                                          
            
    }, "void", ["pointer", "pointer", "pointer", "pointer", "uint32"]);
    retainedHandles.push(callback);
  
    
   



     return callback;
}




function scanMemory(address: NativePointer, numberBytes: number){
    //log("----> scanning the memory from " + address + " to " + address.add(numberBytes));
    for(let i = numberBytes/Process.pointerSize; i >= 0; i--){
        //log("-->address: " + address.add(i * Process.pointerSize) + ", value : " + Memory.readPointer(address.add(i * Process.pointerSize)));
    }
}

function makeMethodExited(): NativePointer {
    const callback = new NativeCallback((self: NativePointer, thread: NativePointer, thisObject: NativePointer, method: NativePointer, dexPc: number, returnValue: NativePointer): void => {
        add_to_log("----->MethodExited() thisObject=" + thisObject + " method=" + method + " JValue=" + returnValue);
    }, "void", ["pointer", "pointer", "pointer", "pointer", "uint32","pointer"]);
    retainedHandles.push(callback);
    return callback;
}

function makeListenerMethod(name: string): NativePointer {
    const callback = new NativeCallback((self: NativePointer, thread: NativePointer): void => {
        add_to_log(name + " was called!");
    }, "void", ["pointer", "pointer"]);
    retainedHandles.push(callback);

    return callback;
}

function makeFieldRead(): NativePointer {
    const callback = new NativeCallback((self: NativePointer, thread: NativePointer, thisObject: NativePointer, method: NativePointer, dexPc: number, field: NativePointer): void => {
        add_to_log("FieldRead() thisObject=" + thisObject + " method=" + method+ " fieldObject="+field);
    }, "void", ["pointer", "pointer", "pointer", "pointer", "uint32","pointer"]);
    retainedHandles.push(callback);

    return callback;
}

function makeFieldWritten(): NativePointer {
    const callback = new NativeCallback((self: NativePointer, thread: NativePointer, thisObject: NativePointer, method: NativePointer, dexPc: number, field: NativePointer, field_value: NativePointer): void => {
        add_to_log("FieldWritten() thisObject=" + thisObject + " method=" + method);
    }, "void", ["pointer", "pointer", "pointer", "pointer", "uint32","pointer","pointer"]);
    retainedHandles.push(callback);

    return callback;
}

function computeRuntimeObjectAddress(): NativePointer {
    //-------------------------> bool Dbg::RequiresDeoptimization()
    const requiresDeoptimization: any = new NativeFunction(
        dlsym(artlib,"_ZN3art3Dbg22RequiresDeoptimizationEv"),
        "bool",
        ["pointer"],
        {
            exceptions: ExceptionsBehavior.Propagate
        });   
    log("***address Of RequiresDeoptimization " + requiresDeoptimization);  
    printAsm(requiresDeoptimization, 10);
    let cur = requiresDeoptimization;
    let pc_page_begin : NativePointer = requiresDeoptimization.shr(12).shl(12); /// just to shit to the beginning of the page, we mimic the adrp instruction on the pc value
                                           /// https://stackoverflow.com/questions/41906688/what-are-the-semantics-of-adrp-and-adrl-instructions-in-arm-assembly
    add_to_log("pc page begin" + pc_page_begin);
    let iterator: number = 0;
    while (true) {
        const insn = Instruction.parse(cur);
        switch (insn.mnemonic) {
            case "adrp":
                const address_read_by_adrp = ptr(insn.operands[1].value);
                add_to_log("address_read_by_adrp " + address_read_by_adrp);
                //after 3 days of looking deeply how to decrypt the instruction, I found this https://reverseengineering.stackexchange.com/questions/15418/getting-function-address-by-reading-adrp-and-add-instruction-values
                //very helpfull: the address printed is already computed from the binary source code as the final value of X8
                add_to_log("final address " + address_read_by_adrp);;

                //When looking at the aarch64 asm code of some functions using the instrumentation object or calling for Runtime->getInstrumentation()
                // I realized that other operations is being made like (from code Dgb::RequiresDeoptimization)
                //ldr x21, [x21, 0x2e0]       ; [0x2e0:4]=-1 ; 736  (the actual pointer I should obtain If I just use the offset computed from my helper)
                //ldr x20, [x21]               // A memory read at this address
                //ldrb w10, [x20, 0x2dc]      // a memory read at the new address plus another offset, to have the forced_interpret_only_ element VALUE of 
                                            //the Instrumentation object in w10, it means the instrumentation object is at this address x20 + 0x2d8 = x2dc - 0x4; 728
                                            //the offset of forced_interpret_only_ returned by the helper and the one used in functions like
                                            //Instrumentation::MethodEnterEventImpl (using have_method_entry_listeners_ as offset 5) are the same
                
                let runtimeOffset_0x2e0 = 736; 
                let asmOptimisationCodeOffset_0x2d8 = 728;//728 because it is (the real offset the offset returned
                                                            //-8 because I considere the real library
                add_to_log("reading the address of art_runtime " + address_read_by_adrp)
                const fake_runtime_x21 = Memory.readPointer(address_read_by_adrp.add(runtimeOffset_0x2e0)); //the cpp storing mecanism is different                                                                          // it should be a simple shift, but more than that we read
                add_to_log(" first line x21 = " + fake_runtime_x21);                                                                                    // Because is it done like that in the asm code (cf up)
                const fake_runtime_x20: NativePointer = Memory.readPointer(fake_runtime_x21);
                 /// I discovered later that the "fake_instrumentation_x20" is the runtime object using asm code of Runtime::CreateImtConflictMethod()
                /// so I will update it for futher use 
                add_to_log("final runtime address " + fake_runtime_x20);;
                return fake_runtime_x20;

                /*let offset_to_shift_relative_to_pc : NativePointer = Memory.readPointer(address_read_by_adrp); // the first 21 bits represent the signed offset
                add_to_log("Offset to use relative to the pc in term of number of pages " + offset_to_shift_relative_to_pc);
                add_to_log("memory dump :");
                add_to_log("" + hexdump(address_read_by_adrp, {
                    offset: 0,dword_size
                    length: 24,
                    header: false,
                    ansi: false
                  }));
                add_to_log("we look for the sign  (shift -->) 63 times");
                let offset_up0_or_down1 = offset_to_shift_relative_to_pc.shr(63);
                let sign = 1;
                if(offset_up0_or_down1){//not zero
                    add_to_log("down 1" + offset_up0_or_down1);
                    // removing the sign
                    offset_to_shift_relative_to_pc = offset_to_shift_relative_to_pc.shl(1).shr(44); // 1 to erase the sign and 64-20 to maitain value
                    add_to_log("real value of the offset  -" + offset_to_shift_relative_to_pc);
                    sign = -1;
                } else {
                    add_to_log("up 0  " + offset_up0_or_down1);
                    offset_to_shift_relative_to_pc = offset_to_shift_relative_to_pc.shr(43);
                    add_to_log("No need to remove the sign" + offset_to_shift_relative_to_pc);
                }
                let big_offset_to_shift_relative_to_pc = offset_to_shift_relative_to_pc.shl(12).toInt32()*sign; // (2^12)
                add_to_log("in term of final number of bytes, final offset " + big_offset_to_shift_relative_to_pc);
                let runtime_addres = pc_page_begin.add(big_offset_to_shift_relative_to_pc);  
                add_to_log("final address " + runtime_addres);*/
                //return runtime_addres;
        }
        cur = insn.next;
        iterator++;
        add_to_log(insn.address + "  -->  " + insn.toString() + "\n");
        if(iterator == 10000){
            print("error!!infinte loop!!"); break;
        }
    }
    add_to_log("ERROR OCCURED");
    return new NativePointer(0);
}


//state of the stack
// arg1
// arg0
// retaddr
// ebp
// <---- esp
type ModuleHandle = NativePointer;
type DlopenFunc = (name: string) => ModuleHandle;
type DlsymFunc = (moduleHandle: ModuleHandle, name: string) => NativePointer;
function getDlopen(): DlopenFunc {
    const impl = Module.findExportByName(null, "dlopen");
    let cur = impl;
    let callsSeen = 0;
    let picValue: any = null;
    let iterator: number = 0;
    add_to_log("--- Printing the process pointer size " + Process.pointerSize);
    while (true) {
        const insn = Instruction.parse(cur);
        switch (insn.mnemonic) {
            case "bl":
                const innerDlopenImpl = ptr(insn.operands[0].value);
                printAsm(innerDlopenImpl, 100);
                return makeDlopenWrapper(innerDlopenImpl); 
           /* case "pop":
                if (insn.operands[0].value === "ebx") {
                    picValue = insn.address;
                }
                break;
            case "add":
                if (insn.operands[0].value === "ebx") {
                    picValue = picValue.add(insn.operands[1].value);
                }
                break;
            case "call":
                callsSeen++;
                if (callsSeen === 2) {
                    const innerDlopenImpl = ptr(insn.operands[0].value);
                    return makeDlopenWrapper(innerDlopenImpl, picValue); 
                }
                break;*/
        }
        cur = insn.next;
        add_to_log(insn.address + "  -->  " + insn.toString() + "\n");
        cur = insn.next;
        iterator++;
    }
}/*
      let prototype_string_offset: number = Memory.readU32(string_ids.add(shorty_idx * 4)); // 
         log("prototype_string offsett old " + prototype_string_offset);
         if(Memory.readPointer(dex_file_begin.add(prototype_string_offset)).equals(NULL)) log("****error in getting the shorty"); 
         let prototype_string_address: NativePointer = dex_file_begin.add(prototype_string_offset + 1);
         log("prototype_string_address : " + prototype_string_address);
         let shorty: any =  Memory.readUtf8String(prototype_string_address);
         add_to_log(" shorty = " + shorty);
*/




function makeDlopenWrapper(innerDlopenImpl: NativePointer/*, picValue: NativePointer*/): DlopenFunc {
    const trampoline = Memory.alloc(Process.pageSize);
    add_to_log("*****making the dlopen wrapper");
    Memory.patchCode(trampoline, 16, code => {
        const cw = new Arm64Writer(code, { pc: trampoline });
        cw.putBranchAddress(innerDlopenImpl);
        cw.flush();
    });
    add_to_log("*****patch code created");
    const innerDlopen: any = new NativeFunction(trampoline, "pointer", ["pointer", "int", "pointer"]);
    const addressInsideLibc = Module.findExportByName("libc.so", "read");

    add_to_log("*****returning the function");
    return function (path: string): NativePointer {
        add_to_log("****call of the dlopen wrapper");
        const handle = innerDlopen(Memory.allocUtf8String(path), 3, addressInsideLibc); //call the real implementation,  but 
                                                                                        // the jump is used in the trampoline 
                                                                                        // to have the same result as if we added 
                                                                                        //other instructions before the real 
                                                                                        //implementation 
                                                                                    
        if (handle.isNull()) {
            add_to_log("***innerDlopen called with error");   
            const dlerror: any = new NativeFunction(Module.findExportByName(null, "dlerror") as NativePointer, "pointer", []);
            throw new Error("Unable to load helper: " + Memory.readUtf8String(dlerror()));
        }
        add_to_log("***innerDlopen called with success: " + handle);   
        return handle;
    };
}/*
function makeDlopenWrapper(innerDlopenImpl: NativePointer, picValue: NativePointer): DlopenFunc {
    const trampoline = Memory.alloc(Process.pageSize);
    Memory.patchCode(trampoline, 16, code => {
        const cw = new X86Writer(code, { pc: trampoline });
        cw.putMovRegAddress("ebx", picValue);
        cw.putJmpAddress(innerDlopenImpl);
        cw.flush();
    });

    const innerModifiedDlopen: any = new NativeFunction(trampoline, "pointer", ["pointer", "int", "pointer"]);
    const addressInsideLibc = Module.findExportByName("libc.so", "read");
    
    //innerDlopen.trampoline = trampoline;

    return function (path: string): NativePointer {
        const handle = innerModifiedDlopen(Memory.allocUtf8String(path), 3, addressInsideLibc);
        if (handle.isNull()) {
            const dlerror: any = new NativeFunction(Module.findExportByName(null, "dlerror") as NativePointer, "pointer", []);
            throw new Error("Unable to load helper: " + Memory.readUtf8String(dlerror()));
        }
        return handle;
    };
}*/
function getDlsym(): DlsymFunc {
    const dlsym: any = new NativeFunction(Module.findExportByName(null, "dlsym") as NativePointer, "pointer", ["pointer", "pointer"]);//possible optimisation (put it outside)
    return function (moduleHandle: ModuleHandle, name: string): NativePointer {
        const address = dlsym(moduleHandle, Memory.allocUtf8String(name));
        if (address.isNull()) {
            throw new Error(`Symbol not found: ${name}`);
        }
        return address;
    };
}


/*/* struct ProtoId {
    dex::StringIndex shorty_idx_;     // index into string_ids array for shorty descriptor
    dex::TypeIndex return_type_idx_;  // index into type_ids array for return type
    uint16_t pad_;                    // padding = 0
    uint32_t parameters_off_;         // file offset to type_list for parameter types

   private:
    DISALLOW_COPY_AND_ASSIGN(ProtoId);
  };*/
function getProtoParameters(protoId: NativePointer, dex_file_begin: NativePointer): NativePointer{
    let result: NativePointer = NULL;
    let parameter_off_: number = Memory.readU32(protoId.add(8));
    if(parameter_off_ != 0){
        result = dex_file_begin.add(parameter_off_);
    }
    return result;
}
function getStringByTypeIndex(type_ids: NativePointer, type_index: number, string_ids: NativePointer, dex_file_begin: NativePointer): string | null{
    //log("-->in function getStringByTypeIndex");
    let type_id =  type_ids.add(type_index*4);
    //add_to_log("getting the string associated to a type: type_id " + type_id);
    let descriptor_idx: number = Memory.readU32(type_id);
    //add_to_log("getting the string associated to a type: descriptor_idx " + descriptor_idx);



    let descriptor_string_offset =  Memory.readU32(string_ids.add(descriptor_idx * 4));
    //add_to_log("getting the string associated to a type: descriptor_string_offset " + descriptor_idx);
    let descriptor_string_address: NativePointer = dex_file_begin.add(descriptor_string_offset + 1);
    //add_to_log("getting the string associated to a type: descriptor_string_address " + descriptor_idx);
    let type_: any = Memory.readUtf8String(descriptor_string_address);
    //add_to_log("getting the string associated to a type: result : " + type_ );
    if(type_.length == 1) return getPrimitiveTypeAsString(type_);
    return type_;
    //In the case we have one character, we need to make type readable 
}
function getPrimitiveTypeAsString(type: any): string|null{
        switch (type) {
            case 'B':
            return "Byte";
            case 'C':
            return "Char";
            case 'D':
            return "Double";
            case 'F':
            return "Float";
            case 'I':
            return "Int";
            case 'J':
            return "Long";
            case 'S':
            return "Short";
            case 'Z':
            return "Boolean";
            case 'V':
            return "Void";
            default:
            return "NotRecognised";
        } 
}
function printAsmExploreCallsGetShorty(impl: NativePointer, nlines: number): void{  
    let counter = 0;
    let cur: NativePointer = impl;
    let callsSeen = 0;
    let ebx: NativePointer = NULL;
    let innerFunction: NativePointer = NULL;
    while (counter < nlines) {    
        const insn = Instruction.parse(cur);
        log(insn.address + "-->  ......... " + insn.toString()); 
        switch (insn.mnemonic) {
            case "call":
                callsSeen++;
                if (callsSeen === 1){
                    log("computing the ebx value");
                    let eax = ptr(insn.operands[0].value);
                    log("eax will have " + eax);
                    ebx = eax.add(ptr("0x13f17")); 
                    log("and ebx =" + ebx);
                }if (callsSeen === 2) {
                    innerFunction = ptr(insn.operands[0].value);
                   
                }
                break;
        } 
        cur = insn.next;  
        counter++; 
        if(insn.mnemonic=="ret") break;
    }
    //log("------> start printing the inner function " + innerFunction);
    printAsm(innerFunction, 1000);
    //log("------> end printing the inner function " + innerFunction);

    let counter_ebx_function = 192;
    counter_ebx_function = counter_ebx_function + 4;
    while (counter_ebx_function <= 1220) {    
        //let dwordfromebx: NativePointer =  ebx.add(ptr(counter_ebx_function));
        //log("--------------> printing dword ptr [ebx + 0x" + counter_ebx_function.toString(16)  + " ]: ");
        printAsm(Memory.readPointer(ebx.add(ptr(counter_ebx_function))), 1000);
        //log("--------------> end printing  dword ptr [ebx + 0x" + counter_ebx_function.toString(16)  + " ]: ");
        counter_ebx_function = counter_ebx_function + 4;
    }

}

function printAsm(impl: NativePointer, nlines: number, force: boolean = false): void{  
    let counter = 0;
    let cur: NativePointer = impl;
    add_to_log("---------------------------> printing the simple asm");
    while (counter < nlines) {    
        const insn = Instruction.parse(cur);
        add_to_log(insn.address + "--> ......... " + insn.toString()); 
        counter++;
        cur = insn.next;  
        counter++; 
        if(insn.mnemonic=="ret" && !force) {add_to_log("!!  instructions not finished");break;}
    }
    add_to_log("----------------------------> end printing simple asm")
}



function patchAttachCurrentThread(): void{
    /*Interceptor.attach(runtimeAttachCurrentThread, {
        onEnter: function (args) {
            //log("---->invokef: called from: " + Thread.backtrace(this.context).map(DebugSymbol.fromAddress).join("\n\t ---->"));
        },
        onLeave: function (retval) {
        }
      });*/
}



/*function printAsmExploreCallsGetShorty(impl: NativePointer, nlines: number): void{  
    let counter = 0;
    let cur: NativePointer = impl;
    let callsSeen = 0;
    let calledFunction: NativePointer = NULL; 
    let picValue: any = null;
    while (counter < nlines) {    
        const insn = Instruction.parse(cur);
        log(insn.address + "-->  ......... " + insn.toString()); 
        switch (insn.mnemonic) {
            case "call":
                callsSeen = callsSeen + 1;
                if(callsSeen == 2){
                    calledFunction = ptr(insn.operands[0].value);
                }    
        }
        cur = insn.next;  
        counter++; 
        if(insn.mnemonic=="ret") break;
    }
    printAsm(calledFunction,1000);
}*/



/* GENERAL COMMENTS

// a bref easy to read code to descripbe how I obtained the shorty

 log("############### My attempt ");            
let proto_index_new: number = proto_index;
log("proto index new: " + proto_index_new);

let proto_id_new: NativePointer = proto_ids.add(proto_index_new * 12);
log("proto_id address new " + proto_id_new);
let shorty_idx_new: NativePointer =  Memory.readPointer(proto_id_new);
log("shorty_idx_new " + shorty_idx_new);



let prototype_string_offset_new: NativePointer = Memory.readPointer(string_ids.add(shorty_idx_new.shl(2)));
log("prototype_string offsett new " + prototype_string_offset_new);

if(Memory.readPointer(dex_file_begin.add(prototype_string_offset_new)).equals(NULL)) log("****error in getting the shorty"); 
let prototype_string_address_new: NativePointer = dex_file_begin.add(prototype_string_offset_new.add(1));
log("prototype_string_address : " + prototype_string_address_new);
log(" first character = " + Memory.readUtf8String(prototype_string_address_new)); 
                            

function called when exploring the getShorty code from a method call. 

function printAsmFirstJump(impl: NativePointer, ebx: NativePointer, nlines: number): void{  
    let counter = 0;
    let cur: NativePointer = impl;
    let jmpsSeen = 0;
    let picValue: any = null;
    let innerFunction1: NativePointer = NULL;
    while (counter < nlines) {    
        const insn = Instruction.parse(cur);
        log(insn.address + "-->  ......... " + insn.toString()); 
        switch (insn.mnemonic) {
            case "jmp":
                jmpsSeen++;
                if (jmpsSeen === 2) {
                    innerFunction1 = ptr(insn.operands[0].value);
                }
                break;       
        }
        cur = insn.next;  
        counter++; 
        if(insn.mnemonic=="ret") break;
    }
    
    log("------> start printing the inner jmp function " + innerFunction1);
    printAsm(innerFunction1, 1000);
    log("------> end printing the inner jmp function " + innerFunction1); 

    let counter_ebx_function = 28;

    let number_ = 12;
    //let dwordfromebx: NativePointer =  ebx.add(ptr(eigth));
    log("--------------> printing dword ptr [ebx + 0x" + number_.toString(16)  + " ]: ");
    let add = Memory.readPointer(ebx.add(ptr(number_))); log("address of code: " + add);
    printAsm(add, 1000);
    log("--------------> end printing  dword ptr [ebx + 0x" + number_.toString(16)  + " ]: ");
    counter_ebx_function = counter_ebx_function + 4;
    while (counter_ebx_function <= 1220) {    
        //let dwordfromebx: NativePointer =  ebx.add(ptr(counter_ebx_function));
        log("--------------> printing dword ptr [ebx + 0x" + counter_ebx_function.toString(16)  + " ]: ");
        printAsm(Memory.readPointer(ebx.add(ptr(counter_ebx_function))), 1000);
        log("--------------> end printing  dword ptr [ebx + 0x" + counter_ebx_function.toString(16)  + " ]: ");
        counter_ebx_function = counter_ebx_function + 4;
    }
}
function printAsmExploreEverything(impl: NativePointer, nlines: number): void{  
    let counter = 0;
    let cur: NativePointer = impl;
    //let callsSeen = 0;
    let picValue: any = null;
    while (counter < nlines) {    
        const insn = Instruction.parse(cur);
        log(insn.address + "-->  ......... " + insn.toString()); 
        switch (insn.mnemonic) {
            case "call":
                const innerFunction = ptr(insn.operands[0].value);
                log("------> start printing the inner function " + innerFunction);
                printAsm(innerFunction,1000);
                log("------> end printing the inner function " + innerFunction);
                break;
        }
        cur = insn.next;  
        counter++; 
        if(insn.mnemonic=="ret") break;
    }
}
function printAsmExploreShorty(impl: NativePointer, nlines: number): void{  
    let counter = 0;
    let cur: NativePointer = impl;GetMethodId
    let callsSeen = 0;
    let ebx: NativePointer = NULL;
    let innerFunction: NativePointer = NULL;
    while (counter < nlines) {    
        const insn = Instruction.parse(cur);
        log(insn.address + "-->  ......... " + insn.toString()); 
        switch (insn.mnemonic) {
            case "call":
                callsSeen++;
                if (callsSeen === 1){
                    log("computing the ebx value");
                    let eax = ptr(insn.operands[0].value);
                    log("eax will have " + eax);
                    ebx = eax.add(ptr("0x15298")); 
                    log("and ebx =" + ebx);
                }if (callsSeen === 2) {
                    innerFunction = ptr(insn.operands[0].value);
                   
                }
                break;
        }
        cur = insn.next;  
        counter++; 
        if(insn.mnemonic=="ret") break;
    }
    log("------> start printing the inner function " + innerFunction);
    printAsmFirstJump(innerFunction, ebx, 1000);
    log("------> end printing the inner function " + innerFunction);
}
old helper an attempts 
---------------------> added inside the interceptor to get args from invoke params but did not work 
if(!invoke_attached){
    patchInvoke(); invoke_attached = 1;
}
// Now I will try to get the shorty from the stack knowing that at this point (execute) an invoke() method has 
// already been called
//void ArtMethod::Invoke(Thread* self, uint32_t* args, uint32_t args_size, JValue* result,const char* shorty)
//  example : method->Invoke(self, shadow_frame->GetVRegArgs(arg_offset),
//                     (shadow_frame->NumberOfVRegs() - arg_offset) * sizeof(uint32_t),result,
//                         method->GetInterfaceMethodIfProxy(kRuntimePointerSize)->GetShorty());
// I plan to continue analysing the stack frame (the matching list) to see if it is like 
//--->the potential shorty at (thread_stack_pointer + 4 * dword_size) contains ???    ;
//--->the potential result at (thread_stack_pointer + 3 * dword_size) contains  result register ;
//--->the potential args_size  at (thread_stack_pointer + 2 * dword_size) contains args_size*Process.pointerSize;
//--->the potential args at (thread_stack_pointer + dword_size) contains shadow_frame_vregs_ + arg_offset;
//--->the potential thread at the current_thread_match already contains readPointer(thread_stack_pointer)
do { 
    let current_thread_stack_pointer: NativePointer = matchList[i].address;
    //log("before the try  current address" + current_thread_stack_pointer);
    try{
        //log("in the try");
        let prospective_method_shorty: NativePointer = Memory.readPointer(current_thread_stack_pointer.sub(dword_size));
        let prospective_args_shorty: NativePointer = Memory.readPointer(current_thread_stack_pointer.add(dword_size));
        if(prospective_method_shorty.equals(prospective_method)){
            //log(" Bingo_Method + args " + prospective_args_shorty); 
            let prospective_shorty: NativePointer = Memory.readPointer(current_thread_stack_pointer.add(4 * dword_size));
            //log(" shorty " + prospective_shorty);
            //log("near to method invoke " + method_Invoke.sub(Memory.readPointer(current_thread_stack_pointer.sub(2 * dword_size))));
            //log(" first character = " + Memory.readUtf8String(prospective_shorty, 1));
            break;
        }  
        
        log("prospective args shorty " + prospective_args_shorty + " method " + prospective_method_shorty);
        if(prospective_args_shorty.equals(args)){
            log("looking for shorty, args are correct");
            let prospective_args_size_shorty: number = Memory.readU32(current_thread_stack_pointer.add(2 * dword_size));
            if(prospective_args_size_shorty == args_size){
                log("looking for shorty, args_size matching");
                let prospective_result_shorty: NativePointer = Memory.readPointer(current_thread_stack_pointer.add(3 * dword_size));
                if(prospective_result_shorty.equals(result_register)){
                    log("looking for shorty, result matching");
                    let shorty: NativePointer =  Memory.readPointer(current_thread_stack_pointer.add(4 * dword_size));
                    log(" Bingo_bingo ! shorty = " + shorty)
                    break;
                }
            }
        }
    } catch (error) {
        log("Error shorty!");
    }   
} while(++i<matchList.length); 

---------------------> trying to get the args from the invoke call, but finally the thread stack showed that it is called before 
function patchInvoke(): void{
    Interceptor.attach(method_Invoke, {
        onEnter: function (args) {
            this.thread = args[1];
            this.args = args[2];
               
        
      
  
        //add_to_log("---------------------------->  unfollowing the current thread" );
        //Stalker.unfollow();
        //add_to_log("----------------------------> end unfollowing the current thread" );
    

            //this.method = args[3];
            //log("invokef: called from: " + Thread.backtrace(this.context).map(DebugSymbol.fromAddress).join("\n\t"));
            //log("MethodEntered()  from the Interceptor ---method=" + this.method + " context=" + JSON.stringify(this.context));
            //log("Loop from the stack pointer " +JSON.stringify(this.context));
            let current_sp = this.context.sp; 
            let dword_size = 4;
            //void ArtMethod::Invoke(Thread* self, uint32_t* args, uint32_t args_size, JValue* result,const char* shorty)
            //--->shorty = sp+dword_size*6;
            //--->result = sp+dword_size*5;
            //--->args_size = sp+dword_size*4;
            //--->args = sp+dword_size*3;
            //--->thread = sp+dword_size*2;
            //--->method = sp+dword_size
            let thread: NativePointer = this.thread;
            this.method = Memory.readPointer(current_sp.add(dword_size));
            let args_ = Memory.readPointer(current_sp.add(dword_size*3));
            let methodNameStringObject = getNameAsString(this.method, thread); 
            const stringMethodName = getNameFromStringObject(methodNameStringObject,thread);
    
            //let args_size = Memory.readU32(current_sp.add(dword_size*4));
            //let current_args = Memory.readPointer(current_sp.add(dword_size*3));
            let prospective_shorty = Memory.readPointer(current_sp.add(dword_size*6));
            //log("---->shorty address = " + prospective_shorty + " thread  = " + this.thread + " args = " + this.args + " method = " + this.method + "-" + stringMethodName);
            //log("---->invokef: called from: " + Thread.backtrace(this.context).map(DebugSymbol.fromAddress).join("\n\t ---->"));

             //log(" first character = " + Memory.readUtf8String(prospective_shorty, 1)); 
            //log("this.threadId = " + this.threadId);
        },
        onLeave: function (retval) {
          //log("-----> Leaving the invoke callback thread = " + this.thread + "args = " + this.args + " method = " + this.method);
        }
      });
}

--------------------->  printing offsets
//const getOffsetOfShadowFrameDexPc: any = new NativeFunction(dlsym(helper, "ath_get_offset_of_shadow_frame_dex_pc_"), "uint", []);
//log("helper think dex_pc is at offset " + getOffsetOfShadowFrameDexPc());
//const getOffsetOfShadowFrameDexPcPtr: any = new NativeFunction(dlsym(helper, "ath_get_offset_of_shadow_frame_dex_pc_ptr_"), "uint", []);
//log("helper think dex_pc_ptr is at offset " + getOffsetOfShadowFrameDexPcPtr());
//const getJitActivated: any = new NativeFunction(dlsym(helper, "ath_get_jit_activated"), "uint", ["pointer"]);
//log("helper think jit activation is  " + getJitActivated(runtime)); //memory_order_relaxed
//const getMemoryOrderRelaxed: any = new NativeFunction(dlsym(helper, "ath_get_memory_order_relaxed"), "uint", []);
//log("helper think memory_order_relaxed is  " + getMemoryOrderRelaxed());
const getCodeItemOffsetOfInsSize: any = new NativeFunction(dlsym(helper, "ath_get_offset_of_code_item_ins_size_"), "uint", []);
//log("helper think offset of ins is  " + getCodeItemOffsetOfInsSize());
const getMethodAccessFlag: any = new NativeFunction(dlsym(helper, "ath_get_method_field_"), "uint", []);
//log("helper think offset of fied is  " + getMethodAccessFlag());
const getShadowFrameOffsetOfVregs: any = new NativeFunction(dlsym(helper, "ath_get_shadow_frame_vregs_"), "uint", []); 
//log("helper think offset of vregs  " + getShadowFrameOffsetOfVregs());
const method_Invoke: any = new NativeFunction(
    dlsym(artlib,"_ZN3art9ArtMethod6InvokeEPNS_6ThreadEPjjPNS_6JValueEPKc"),
    "void",
    ["pointer","pointer","uint32","pointer","pointer"],
    {
        exceptions: ExceptionsBehavior.Propagate
    });
log("printing the address of  checkJni:CheckMethodAndSig " + method_Invoke);

----------------------->attempt to print asm code from function pointer of inlined methods (do not work) 
//const getShortyMethodAddress: any = new NativeFunction(dlsym(helper, "ath_get_shorty_address"), "pointer", []);
//log("getting the shorty address " + getShortyMethodAddress);
//printAsm(getShortyMethodAddress,1000);
//const getInterfaceMethodIfProxyAddress: any = new NativeFunction(dlsym(helper, "ath_get_interface_if_proxy_address"), "pointer", ["pointer"]);
//log("getting the getInterfaceMethodIfproxy address " + getInterfaceMethodIfProxyAddress);
//printAsm(getInterfaceMethodIfProxyAddress,1000);

----------------------> attempt to print asm of function calling getShorty or getInterfaceMethodIfProxy
const artQuickToInterpreterBridge: any = new NativeFunction(
    dlsym(artlib,"artQuickToInterpreterBridge"),
    "uint64",
    ["pointer","pointer","pointer"],
    {
        exceptions: ExceptionsBehavior.Propagate
});
log("###########printing the address of  artQuickToInterpreterBridge " + artQuickToInterpreterBridge);
const ExecuteMterpImpl: any = new NativeFunction(
dlsym(artlib,"ExecuteMterpImpl"),
"bool",
["pointer","pointer","pointer","pointer"],
{
    exceptions: ExceptionsBehavior.Propagate
});
log("printing the address of  ExecuteMterpImpl " + ExecuteMterpImpl);
printAsm(ExecuteMterpImpl, 1000);
const checkVarArgs: any = new NativeFunction(
    dlsym(artlib,"_ZN3art11ScopedCheck12CheckVarArgsERNS_18ScopedObjectAccessEPKNS_7VarArgsE"),
    "bool",
    ["pointer","pointer"],
    {
        exceptions: ExceptionsBehavior.Propagate
    });
log("printing the address of  checkVarArgs " + checkVarArgs);
printAsm(checkVarArgs, 100000);
const ArtInterpreterToCompiledCodeBridge: any = new NativeFunction(
    dlsym(artlib,"_ZN3art11interpreter34ArtInterpreterToCompiledCodeBridgeEPNS_6ThreadEPNS_9ArtMethodEPNS_11ShadowFrameEtPNS_6JValueE"),
    "bool",
    ["pointer","pointer","pointer","uint16","pointer"],
    {
        exceptions: ExceptionsBehavior.Propagate
    });
log("printing the address of  ArtInterpreterToCompiledCodeBridge " + ArtInterpreterToCompiledCodeBridge);
printAsm(ArtInterpreterToCompiledCodeBridge, 100000);
_ZN3art11ScopedCheck12CheckVarArgsERNS_18ScopedObjectAccessEPKNS_7VarArgsE
const checkJni_CheckMethodAndSig: any = new NativeFunction(
    dlsym(artlib,"_ZN3art11ScopedCheck17CheckMethodAndSigERNS_18ScopedObjectAccessEP8_jobjectP7_jclassP10_jmethodIDNS_9Primitive4TypeENS_10InvokeTypeE"),
    "bool",
    ["pointer","pointer","pointer","pointer","uint32","uint32"],
    {
        exceptions: ExceptionsBehavior.Propagate
    });
log("printing the address of  checkJni:CheckMethodAndSig " + checkJni_CheckMethodAndSig);
printAsm(checkJni_CheckMethodAndSig, 1000);
const gdb_OutputMethodReturnValue: any = new NativeFunction(
    dlsym(artlib,"_ZN3art3Dbg23OutputMethodReturnValueEyPKNS_6JValueEPNS_4JDWP9ExpandBufE"),
    "void",
    ["uint64","pointer","pointer"],
    {
        exceptions: ExceptionsBehavior.Propagate
    });
log("printing the address of gdb::OutputMethodReturnValue " + gdb_OutputMethodReturnValue);
log("code : \n ");
printAsm(gdb_OutputMethodReturnValue, 1000);
const Executable_CreateFromArtMethod: any = new NativeFunction(
    dlsym(artlib,"_ZN3art6mirror10Executable19CreateFromArtMethodILNS_11PointerSizeE4ELb1EEEbPNS_9ArtMethodE"),
    "bool",
    ["pointer"],
    {
        exceptions: ExceptionsBehavior.Propagate
    });
log("printing the address of  Executable::CreateFromArtMethod " + Executable_CreateFromArtMethod);
log("code : \n ");
printAsm(Executable_CreateFromArtMethod, 1000);
const trace_GetMethodLine : any = new NativeFunction(
    dlsym(artlib,"_ZN3art5Trace13GetMethodLineEPNS_9ArtMethodE"),
    "pointer",
    ["pointer"],
    {
        exceptions: ExceptionsBehavior.Propagate
    });
log("printing the address of  Trace::GetMethodLine " + trace_GetMethodLine);
log("code : \n ");
printAsm(trace_GetMethodLine, 1000);  
const classLinker_SetIMTRef  : any = new NativeFunction(
    dlsym(artlib,"_ZN3art11ClassLinker9SetIMTRefEPNS_9ArtMethodES2_S2_PbPS2_"),
    "pointer",
    ["pointer"],
    {
        exceptions: ExceptionsBehavior.Propagate
    });
log("printing the address of  classLinker_SetIMTRef" + classLinker_SetIMTRef);
log("code : \n ");
printAsm(classLinker_SetIMTRef, 1000);

-------------------------> some other helper code 
log(" -- forced_interpret_only_ value is : " + Memory.readS8(instrumentation.add(Process.pointerSize)) );
log(" -- deoptimization_enabled value is : " + Memory.readS8(instrumentation.add(203)) );
let i = 0
for (i = 0; i<= 216 ; i++){
    if (Memory.readS8(instrumentation.add(216-i)) == 0 || Memory.readS8(instrumentation.add(216-i)) == 1)
    {log("boolean offset : " + (216-i) + "value : " + Memory.readS8(instrumentation.add(216-i)));}
} 
    HELPER CODE
        log("preparing and call deoptimization");
        const prepareDoptimization: any = new NativeFunction(
        dlsym(helper, "ath_prepare_call_deoptimisation"), 
        "pointer", 
        ["pointer","pointer","pointer"]
        ,{
            exceptions: ExceptionsBehavior.Propagate
     });
     /log(`helper module: ${helper.toString()}`);
        /*const getOffsetOfRuntimeInstrumentation: any = new NativeFunction(dlsym(helper, "ath_get_offset_of_runtime_instrumentation"), "uint", []);
        log("we think instrumentation is at offset " + instrumentationOffset + ", helper thinks it's at " + getOffsetOfRuntimeInstrumentation());    
        
        const getOffsetOfClassIftable: any = new NativeFunction(dlsym(helper, "ath_get_offset_of_class_iftable_"), "uint", []);
        log("we think  types ids is at offset " + 16 + ", helper thinks it's at " + getOffsetOfClassIftable());    
        */

        
        //const getMethoyTryCallShorty: any = new NativeFunction(dlsym(helper, "ath_get_method_try_call_shorty"), "pointer", ["pointer"]);
        //log("///////looking inside the getShorty() source code");
        //printAsmExploreShorty(getMethoyTryCallShorty, 1000);
        //const getMethoyTryCallGetInterfaceIfProxy: any = new NativeFunction(dlsym(helper, "ath_get_method_try_call_get_interface_if_proxy"), "pointer", ["pointer"]);
        //log("helper think ath_get_method_try_call_shorty is  " + getMethoyTryCallShorty());
        //log("getInterfaceMethodIfProxy()");
        //printAsmExploreShorty(getMethoyTryCallGetInterfaceIfProxy, 1000);
        //const getMethodShorty: any = new NativeFunction(dlsym(helper, "ath_get_method_shorty_"), "pointer", ["pointer"]);
        /*log("method Shorty code ");
        printAsm(getMethodShorty, 1000);*/
        /*const helperGetShorty: any = new NativeFunction(
        dlsym(helper,"_ZN3art9ArtMethod9GetShortyEv"),
        "pointer",
        [],
        {
            exceptions: ExceptionsBehavior.Propagate
        });
        log("address of getShorty in the helper" + helperGetShorty);*/
        //printAsmExploreCallsGetShorty(helperGetShorty,1000)
       
       //log("address of runtimeAttachCurrentThread in the helper" + runtimeAttachCurrentThread);
        //printAsmExploreCallsGetShorty(helperGetShorty,1000)
    
    
        /*const mirror_FindDeclaredDirectMethodByName: any = new NativeFunction(
        dlsym(artlib,"_ZN3art6mirror5Class30FindDeclaredDirectMethodByNameERKNS_11StringPieceENS_11PointerSizeE"),
        "pointer",
        ["pointer","pointer"],
        {
            exceptions: ExceptionsBehavior.Propagate
        });
        log("printing the address of mirror_FindDeclaredDirectMethodByName " + mirror_FindDeclaredDirectMethodByName);
        log("code : \n ");
        printAsm(mirror_FindDeclaredDirectMethodByName, 1000);*/

        /*const instrumentationListener_MethodExited: any = new NativeFunction(
        dlsym(artlib,"_ZN3art15instrumentation23InstrumentationListener12MethodExitedEPNS_6ThreadENS_6HandleINS_6mirror6ObjectEEEPNS_9ArtMethodEjS7_"),
        "void",
        ["pointer","pointer","pointer","uint32","pointer"],
        {
            exceptions: ExceptionsBehavior.Propagate
        });
        log("printing the address of instrumentationListener_MethodExited " + instrumentationListener_MethodExited);
        log("code : \n ");
        printAsm(instrumentationListener_MethodExited, 1000);
    
        const trace_GetMethodLine: any = new NativeFunction(
        dlsym(artlib,"_ZN3art5Trace13GetMethodLineEPNS_9ArtMethodE"),
        "pointer",
        ["pointer"],
        {
            exceptions: ExceptionsBehavior.Propagate
        });
        log("printing the address of Trace::GetMethodLine " + trace_GetMethodLine);
        log("code : \n ");
        printAsm(trace_GetMethodLine, 1000);
-----------------------> modification needed to activate the deoptimization directly in the app config
to test in app <application
android:icon="@mipmap/ic_launcher"
android:label="@string/app_name"
android:vmSafeMode="true">

------------------------> some codes used to test the deoptimization enabling before finally using java.perform
const myForceInterpretOnly: any = new NativeFunction(dlsym(helper, "ath_instrumentation_force_interpret_only"), "void", ["pointer"]);
log("before force_interpret_only_call");
let i = 0;
for (i = 0; i<= 216 ; i++){
    if (Memory.readS8(instrumentation.add(216-i)) == 0 || Memory.readS8(instrumentation.add(216-i)) == 1)
    {log("boolean offset : " + (216-i) + "value : " + Memory.readS8(instrumentation.add(216-i)));}
}
myForceInterpretOnly(instrumentation);
log("after force_interpret_only_call");
for (i = 0; i<= 216 ; i++){
    if (Memory.readS8(instrumentation.add(216-i)) == 0 || Memory.readS8(instrumentation.add(216-i)) == 1)
    {log("boolean offset : " + (216-i) + "value : " + Memory.readS8(instrumentation.add(216-i)));}
}

-------------------------> useful mangled function to manipulate the scope
"_ZN3art2gc23ScopedGCCriticalSectionD1Ev",
    "_ZN3art2gc23ScopedGCCriticalSectionD2Ev",
    "_ZN3art2gc23ScopedGCCriticalSectionC2EPNS_6ThreadENS0_7GcCauseENS0_13CollectorTypeE",
    "_ZN3art2gc23ScopedGCCriticalSectionC1EPNS_6ThreadENS0_7GcCauseENS0_13CollectorTypeE"

-----------------------> log related to the shadow frame processing in the function Interpreter::Execute()    
let address_in_execute = Memory.readPointer(thread_stack_pointer.sub(dword_size));
log("address in execute " + address_in_execute);
log("Patching the invoke");

-----------------------> code of dlopen used to create the trampoline
                                                            push ebp
02-27 10:58:10.617  7144  7144 I frida   : 0xf1bd0ef1  -->  mov ebp, esp
02-27 10:58:10.617  7144  7144 I frida   : 0xf1bd0ef3  -->  push ebx
02-27 10:58:10.617  7144  7144 I frida   : 0xf1bd0ef4  -->  and esp, 0xfffffff0
02-27 10:58:10.617  7144  7144 I frida   : 0xf1bd0ef7  -->  sub esp, 0x10
02-27 10:58:10.617  7144  7144 I frida   : 0xf1bd0efa  -->  call 0xf1bd0eff
02-27 10:58:10.617  7144  7144 I frida   : 0xf1bd0eff  -->  pop ebx
02-27 10:58:10.617  7144  7144 I frida   : 0xf1bd0f00  -->  add ebx, 0x20a1
02-27 10:58:10.618  7144  7144 I frida   : 0xf1bd0f06  -->  sub esp, 4
02-27 10:58:10.618  7144  7144 I frida   : 0xf1bd0f09  -->  push dword ptr [ebp + 4]
02-27 10:58:10.618  7144  7144 I frida   : 0xf1bd0f0c  -->  push dword ptr [ebp + 0xc]
02-27 10:58:10.618  7144  7144 I frida   : 0xf1bd0f0f  -->  push dword ptr [ebp + 8]
02-27 10:58:10.618  7144  7144 I frida   : 0xf1bd0f12  -->  call 0xf1bd0d10
02-27 10:58:10.626  7144  7144 I frida   : 0xf1bd0f17  -->  add esp, 0x10
02-27 10:58:10.626  7144  7144 I frida   : 0xf1bd0f1a  -->  lea esp, [ebp - 4]
02-27 10:58:10.627  7144  7144 I frida   : 0xf1bd0f1d  -->  pop ebx
02-27 10:58:10.627  7144  7144 I frida   : 0xf1bd0f1e  -->  pop ebp
02-27 10:58:10.627  7144  7144 I frida   : 0xf1bd0f1f  -->  ret   ----
02-27 10:58:10.627  7144  7144 I frida   : 0xf1bd0f20  -->  push ebp
02-27 10:58:10.627  7144  7144 I frida   : 0xf1bd0f21  -->  mov ebp, esp
02-27 10:58:10.627  7144  7144 I frida   : 0xf1bd0f23  -->  push ebx
02-27 10:58:10.627  7144  7144 I frida   : 0xf1bd0f24  -->  and esp, 0xfffffff0
02-27 10:58:10.627  7144  7144 I frida   : 0xf1bd0f27  -->  sub esp, 0x10
02-27 10:58:10.627  7144  7144 I frida   : 0xf1bd0f2a  -->  call 0xf1bd0f2f
02-27 10:58:10.627  7144  7144 I frida   : 0xf1bd0f2f  -->  pop ebx
02-27 10:58:10.628  7144  7144 I frida   : 0xf1bd0f30  -->  add ebx, 0x2071
02-27 10:58:10.628  7144  7144 I frida   : 0xf1bd0f36  -->  call 0xf1bd0d20
02-27 10:58:10.628  7144  7144 I frida   : 0xf1bd0f3b  -->  lea esp, [ebp - 4]
02-27 10:58:10.628  7144  7144 I frida   : 0xf1bd0f3e  -->  pop ebx
02-27 10:58:10.628  7144  7144 I frida   : 0xf1bd0f3f  -->  pop ebp
02-27 10:58:10.628  7144  7144 I frida   : 0xf1bd0f40  -->  ret
02-27 10:58:10.628  7144  7144 I frida   : 0xf1bd0f41  -->  jmp 0xf1bd0f50
02-27 10:58:10.628  7144  7144 I frida   : 0xf1bd0f43  -->  nop

------------------------> first attemps to get the current stack
// I will use the managed stack (offset 140 of the thread Object)
let managed_stack  = thread.add(140);
log("---Managed stack=" + managed_stack);       
// try to access the shadow stack (it is private but we don't care??? Ole answer)
let shadow_frame_from_managed_stack = Memory.readPointer(managed_stack.add(2 * Process.pointerSize));
log("-Shadow frame from managed stack =" + shadow_frame_from_managed_stack);
let art_method_0 = shadow_frame_from_managed_stack.isNull() ? new NativePointer(0) : Memory.readPointer(shadow_frame_from_managed_stack.add(1*Process.pointerSize));
log("-corresponding method =" + art_method_0);
    //just to test offset
let dex_pc_ptr_val_managed_stack= shadow_frame_from_managed_stack.isNull() ? null : Memory.readU32(shadow_frame_from_managed_stack.add(4*Process.pointerSize));
log("dex_pc =" + dex_pc_ptr_val_managed_stack);
//just test the method
if(!art_method_0.isNull()) log("-/testing this method : (dex_method_index_) " +  Memory.readU32(art_method_0.add(8)));
let top_quick_frame_add = Memory.readPointer(managed_stack);  
log("-Top quick frame from managed stack =" + top_quick_frame_add);
let art_method_1 = top_quick_frame_add.isNull() ? new NativePointer(0) : Memory.readPointer(top_quick_frame_add);
log("-Corresponding method : " + art_method_1); /// because the quick frame contains pointer to methods. 
//just test the method
if(!art_method_1.isNull()) log("-/testing this method : (dex_method_index_) " +  Memory.readU32(art_method_1.add(8)));
// We can also use the instrumentation stack *
let instrumentation_stack = Memory.readPointer(thread.add(208));
log("-Instrumentation stack handle=" + instrumentation_stack);
let instrumentationStack : StdInstrumentationStackDeque = new StdInstrumentationStackDeque(instrumentation_stack);
let front_frame = instrumentationStack.front();
log("-----front frame of the instrumentation stack = " + front_frame);
let art_method_front =  front_frame.isNull() ? new NativePointer(0) : Memory.readPointer(front_frame.add(1 * Process.pointerSize));
log("-Corresponding method : " + art_method_front);
//just to test offset
let interpreter_entry_front= front_frame.isNull() ? null : Memory.readInt(front_frame.add(16));
log("interpreter_entry_ =" + interpreter_entry_front);
//just test the method
if(!art_method_front.isNull()) log("-/testing this method : (dex_method_index_)" +  Memory.readU32(art_method_front.add(8)));
let back_frame = instrumentationStack.back();
log("-----back frame of the instrumentation stack = " + back_frame);
let art_method_back =  back_frame.isNull() ? new NativePointer(0) : Memory.readPointer(back_frame.add(1 * Process.pointerSize));
log("-Corresponding method : " + art_method_back);
//just to test offset
let interpreter_entry_back= back_frame.isNull() ? null : Memory.readInt(back_frame.add(16));
log("interpreter_entry_ =" + interpreter_entry_back);
//just test the method
if(!art_method_back.isNull()) log("-/testing this method : (dex_method_index_)" +  Memory.readU32(art_method_back.add(8)));  

-----------------------> method used to process the libc array
end(): NativePointer {
// defined at line 1086 https://github.com/llvm-mirror/libcxx/blob/master/include/deque
// we ignore the iterator 
// supposing that the second arg of __mp it contains the address of the element we want 
// (it second is the one retrived when referencing the iterator at line 318)
this.refresh();
log("---  we get the end"); 
let __p : number = this.size() + this.__start_;
log(" value of p " + __p); 
let  __mp : NativePointer = this.__map_begin().add(  Math.floor(__p / this.__block_size)) ;
log (" processing the __mp : " + __mp + " with ratio p/size : " +  Math.floor(__p / this.__block_size)
                            + " p%size = " + __p % this.__block_size);
let result : NativePointer = this.__map_empty() ? 
                                new NativePointer(0) :
                                Memory.readPointer(__mp).add((__p % this.__block_size));
log("final result " + result );
return result;
}


------------------------------> // by direclyty looking inside the shadow frame, the caller is not avalaible see the code in the draft. 
                            let link_shadow_frame: NativePointer = Memory.readPointer(prospective_shadowFrame);
                            if(link_shadow_frame.isNull){
                                log("caller name is not avalaible");
                            }else{
                                log("caller shadow frame address " + link_shadow_frame);
                                let link_method: NativePointer = Memory.readPointer(link_shadow_frame.add(1*Process.pointerSize));
                                let linkMethodNameStringObject = getNameAsString(link_method, thread); 
                                const stringLinkMethodName = getNameFromStringObject(linkMethodNameStringObject,thread);
                                log("caller Method : " + stringLinkMethodName);

                                let rawLinkClassName: string;
                                const storage = new StdString();
                                const link_declaring_classHandle= link_method.add(declaringClassOffset);
                                const link_declaring_class_ = ptr(Memory.readU32(link_declaring_classHandle));
                                rawLinkClassName = Memory.readUtf8String(getDescriptor(link_declaring_class_, storage)) as string;   
                                storage.dispose();
                                const link_className = rawLinkClassName.substring(1, rawLinkClassName.length - 1).replace(/\//g, ".");
                                log("caller class Name" + link_className);
                            }


----------------------------->testing the odile logger
----------------------------->helper code on the phone
        add_to_log("****getting offset of art_instrumentation object");
        const getOffsetOfRuntimeInstrumentation: any = new NativeFunction(dlsym(helper, "ath_get_offset_of_runtime_instrumentation"), "uint", []);
        let instrumentationOffset = getOffsetOfRuntimeInstrumentation();
        log("****instrumentation offset is  " + instrumentationOffset);    
                            
     looking at lists offsets 
        add_to_log("****getting the requested_instrumentation_levels_ offset");
        const getOffsetOfRequestedInstrumentationLevel: any = new NativeFunction(dlsym(helper, "ath_get_offset_of_instrumentation_requested_instrumentation_levels_"), "uint", []);
        let offsetOfRequestedInstrumentationLevel: number =   getOffsetOfRequestedInstrumentationLevel();
        add_to_log("**** offset of requested_instrumentation_levels_ " + offsetOfRequestedInstrumentationLevel);

        add_to_log("****getting the method_entry_listeners_ offset");//352 on the phone
        const getOffsetOfMethodEntryListeners: any = new NativeFunction(dlsym(helper, "ath_get_offset_of_instrumentation_method_entry_listeners_"), "uint", []);
        let offsetOfMethodEntryListeners: number =   getOffsetOfMethodEntryListeners();
        add_to_log("**** offset of method_entry_listeners_ " + offsetOfMethodEntryListeners);

        add_to_log("****getting the method_exit_listeners_ offset");//352 on the phone
        const getOffsetOfMethodExitListeners: any = new NativeFunction(dlsym(helper, "ath_get_offset_of_instrumentation_method_exit_listeners_"), "uint", []);
        let offsetOfMethodExitListeners: number =   getOffsetOfMethodExitListeners();
        add_to_log("**** offset of method_exit_listeners_ " + offsetOfMethodExitListeners);

        add_to_log("****getting the method_unwind_listeners_ offset");//352 on the phone
        const getOffsetOfMethodUnwindListeners: any = new NativeFunction(dlsym(helper, "ath_get_offset_of_instrumentation_method_unwind_listeners_"), "uint", []);
        let offsetOfMethodUnwindListeners: number =   getOffsetOfMethodUnwindListeners();
        add_to_log("**** offset of method_unwind_listeners_ " + offsetOfMethodUnwindListeners);

        add_to_log("****getting the branch_listeners_ offset");//352 on the phone
        const getOffsetOfBranchListeners: any = new NativeFunction(dlsym(helper, "ath_get_offset_of_instrumentation_branch_listeners_"), "uint", []);
        let offsetOfBranchListeners: number =   getOffsetOfBranchListeners();
        add_to_log("**** offset of branch_listeners_ " + offsetOfBranchListeners);

        add_to_log("****getting the invoke_virtual_or_interface_listeners_ offset");//352 on the phone
        const getOffsetInvokeVirtualOrInterfaceListeners: any = new NativeFunction(dlsym(helper, "ath_get_offset_of_instrumentation_invoke_virtual_or_interface_listeners_"), "uint", []);
        let offsetOfInvokeVirtualOrInterfaceListeners: number =   getOffsetInvokeVirtualOrInterfaceListeners();
        add_to_log("**** offset of invoke_virtual_or_interface_listeners_ " + offsetOfInvokeVirtualOrInterfaceListeners);

        add_to_log("****getting the field_read_listeners_ offset");//352 on the phone
        const getOffsetOfFieldReadListeners: any = new NativeFunction(dlsym(helper, "ath_get_offset_of_instrumentation_field_read_listeners_"), "uint", []);
        let offsetFieldReadListeners: number =   getOffsetOfFieldReadListeners();
        add_to_log("**** offset of field_read_listeners_ " + offsetFieldReadListeners);


        add_to_log("****getting the field_write_listeners_ offset");//352 on the phone
        const getOffsetOfFieldWriteListeners: any = new NativeFunction(dlsym(helper, "ath_get_offset_of_instrumentation_field_write_listeners_"), "uint", []);
        let offsetFieldWriteListeners: number =   getOffsetOfFieldWriteListeners();
        add_to_log("**** offset of field_write_listeners_ " + offsetFieldWriteListeners);


        add_to_log("****getting the exception_caught_listeners_ offset");//352 on the phone
        const getOffsetOfExceptionCaughtListeners: any = new NativeFunction(dlsym(helper, "ath_get_offset_of_instrumentation_exception_caught_listeners_"), "uint", []);
        let offsetOfExceptionCaughtListeners: number =   getOffsetOfExceptionCaughtListeners();
        add_to_log("**** offset of exception_caught_listeners_ " + offsetOfExceptionCaughtListeners);


        add_to_log("****getting the deoptimized_methods_lock_listeners_ offset");//352 on the phone
        const getOffsetOfDeoptimizedMethodLockListeners: any = new NativeFunction(dlsym(helper, "ath_get_offset_of_instrumentation_deoptimized_methods_lock_listeners_"), "uint", []);
        let offsetOfDeoptimizedMethodLockListeners: number =   getOffsetOfDeoptimizedMethodLockListeners();
        add_to_log("**** offset of deoptimized_method_lock_listeners_ " + offsetOfDeoptimizedMethodLockListeners);

        add_to_log("****getting the deoptimized_methods_listeners_ offset");//352 on the phone
        const getOffsetOfDeoptimizedMethodListeners: any = new NativeFunction(dlsym(helper, "ath_get_offset_of_instrumentation_deoptimized_methods_listeners_"), "uint", []);
        let offsetOfDeoptimizedMethodListeners: number =   getOffsetOfDeoptimizedMethodListeners();
        add_to_log("**** offset of deoptimized_method_listeners_ " + offsetOfDeoptimizedMethodListeners); 
 

        Printing the asm of some methods
         testing the offset of instrumenation by looking manually the asm code of some functions 
        //-------------------------> void Dbg::ProcessDeoptimizationRequest(const DeoptimizationRequest& request)
        const ProcessDeoptimizationRequest: any = new NativeFunction(
            dlsym(artlib,"_ZN3art3Dbg28ProcessDeoptimizationRequestERKNS_21DeoptimizationRequestE"),
            "void",
            ["pointer", "pointer"],
            {
                exceptions: ExceptionsBehavior.Propagate
            });   
        add_to_log("***address Of ProcessDeoptimizationRequest " + ProcessDeoptimizationRequest);  
        add_to_log("instructions : \n"); printAsm(ProcessDeoptimizationRequest,1000);
        
        //-------------------------> bool Dbg::IsForcedInterpreterNeededForResolutionImpl(Thread* thread, ArtMethod* m)
        const IsForcedInterpreterNeededForResolutionImpl: any = new NativeFunction(
            dlsym(artlib,"_ZN3art3Dbg42IsForcedInterpreterNeededForResolutionImplEPNS_6ThreadEPNS_9ArtMethodE"),
            "bool",
            ["pointer", "pointer", "pointer"],
            {
                exceptions: ExceptionsBehavior.Propagate
            });   
        add_to_log("***address Of IsForcedInterpreterNeededForResolutionImpl " + IsForcedInterpreterNeededForResolutionImpl);  
        add_to_log("instructions : \n"); printAsm(IsForcedInterpreterNeededForResolutionImpl,1000);
        
         
        //-------------------------> bool Dbg::IsForcedInterpreterNeededForUpcallImpl(Thread* thread, ArtMethod* m)
        const IsForcedInterpreterNeededForUpcallImpl: any = new NativeFunction(
            dlsym(artlib,"_ZN3art3Dbg38IsForcedInterpreterNeededForUpcallImplEPNS_6ThreadEPNS_9ArtMethodE"),
            "bool",
            ["pointer", "pointer", "pointer"],
            {
                exceptions: ExceptionsBehavior.Propagate
            });   
        add_to_log("***address Of IsForcedInterpreterNeededForUpcallImpl " + IsForcedInterpreterNeededForUpcallImpl);  
        add_to_log("instructions : \n"); printAsm(IsForcedInterpreterNeededForUpcallImpl,1000);

      
        //-------------------------> bool Dbg::RequiresDeoptimization()
        const RequiresDeoptimization: any = new NativeFunction(
            dlsym(artlib,"_ZN3art3Dbg22RequiresDeoptimizationEv"),
            "bool",
            ["pointer"],
            {
                exceptions: ExceptionsBehavior.Propagate
            });   
        add_to_log("***address Of RequiresDeoptimization " + RequiresDeoptimization);  
        add_to_log("instructions : \n"); printAsm(RequiresDeoptimization,1000);
        
        last option
          ThreadPool.schedule(function () {
        Java.perform(function () {
            blockingJavaCall();
        });
        }); 
        
        //Testing interceptor.replace
           //to del 
        Interceptor.replace(enableDeoptimization, new NativeCallback( function (this: NativePointer, thread: NativePointer) {
            add_to_log("---->enable deoptimization in the replaced script ");
            let me  = this as unknown;
            let mee = me as InvocationContext;
            let context = mee.context;
            add_to_log("---->enable deoptimization from the replaced script " + context);
        }, "void", ["pointer"]));
        add_to_log("before the test replace call, deoptimisation_enable = " + deoptimisation_enabled);
        //enableDeoptimization(instrumentation/*.add(200 * Process.pointerSize));
        //add_to_log("after the test replace call, deoptimisation_enable = " + deoptimisation_enabled);
        // end to del


Méthode complète à priori d'interception via le stalker
var a_function = Module.findExportByName(null, 'write');
var my_callprobe = Stalker.addCallProbe(a_function, function(args){
    console.log('In my callback');
});
Process.enumerateThreads({
    onMatch: function(t) {
        console.log('Found thread');
        Stalker.follow(Process.getCurrentThreadId(), {
            events:{
                call:true
            }
        });
    },
    onComplete: function(){
        console.log('Completed');
    }
});

// /*Interceptor.attach(callback, {
        onEnter: function (args) {
        
            add_to_log("----------------------------> !!!!!!!!!!!!!!OnEnter on CALLBACK from interceptor" + this.context)
            
        },   
        
      
  
        //add_to_log("---------------------------->  unfollowing the current thread" );
        //Stalker.unfollow();
        //add_to_log("----------------------------> end unfollowing the current thread" );
    

    });*/
    /*Interceptor.attach(callback, {
        onEnter: function (args) {
        
            add_to_log("----------------------------> !!!!!!!!!!!!!!OnEnter on CALLBACK from interceptor")
            
        },
    });*/
    /*Interceptor.replace(callback, new NativeCallback( function (this: InvocationContext, thread: NativePointer, thisObject: NativePointer, 
        method: NativePointer, dexPc: number) {
            add_to_log("---->method entered from the replaced script ");
            let context = this.context;
            add_to_log("---->method entered from the replaced script " + context);
      },"void", ["pointer", "pointer", "pointer", "pointer", "uint32"]));*/
    /*Java.perform(() => {
        add_to_log("java perform when building the callback");
        retainedHandles.push(callback);
        Interceptor.attach(callback, {
            onEnter: function (args) {
            
                add_to_log("----------------------------> !!!!!!!!!!!!!!OnEnter on CALLBACK")
                
            },
        });
        //we attach an interceptor to callback to have access to the stack of the current thread
        //to optimize----------------

        /*let native_function = new NativeFunction(callback, "void",
        ["pointer","pointer","pointer","pointer","uint32"],
        {
            exceptions: ExceptionsBehavior.Propagate
        });
        Interceptor.attach(native_function, {
            onEnter: function (args) {
            
                add_to_log("----------------------------> !!!!!!!!!!!!!!OnEnter on CALLBACK")
                
            },
        });
    

     //});     
     
     // WHEN TESTING THREAD ID AND LIBART  OFFSET
     try {
            
        //////  The context I want should refer to the art lib in memory because it calls my listener, 
        ////// I consider that the context is not good when is pc is lower than the base address of libart
        //////  meaning that the function I'm looking for in the backtrace is not in libart. 
        ////// to compute the base address,
        /////  I computed the ADSL offset using 1- the correct address of DeoptimizeEverething obtained with radare2 0x00250374 and 2 - the dynamic address obtained before in this code. 
        /////  
        
        if(context.pc.compare(baseAddress) >= 0){
            ///// I also test the current thread, if it is the main one (it id should be the same as the process id)
            // if(Process.id == mainThread.id) {
            let current_thread_id_3 = Process.getCurrentThreadId();
            threads.forEach(function (thread) {
                //add_to_log('testing the thread ' + thread.id);   
                //add_to_log('current thread ' + current_thread_id_3);  
                if( current_thread_id_3 == thread.id){
                    //add_to_log("this thread is correct !! ");
                    mainThread_3 = thread;
                }
            });     

            /*add_to_log("-----> Process id : " + Process.id + ", number of threads " + threads.length + ",  mainthread id: " + mainThread.id + 
            " \n current Thread  first value : " 
            + current_thread_id_1 + " \n context of the first current thread " + JSON.stringify(mainThread_1.context) + 
            " \n current Thread second value: " + current_thread_id_2
            + " \n context of the second current thread" + JSON.stringify(mainThread_2.context)
            + "\n current Thread third value: " + current_thread_id_3
            + " \n context of the third current thread" + JSON.stringify(mainThread_3.context));
            
                
            Thread.sleep(0.5);
            add_to_log("#####>before calling backtrace context " + JSON.stringify(mainThread_3.context));

            //let backtrace = Thread.backtrace(mainThread_3.context, Backtracer.ACCURATE);
            let backtrace = Thread.backtrace(mainThread_3.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join("\n\t#####>");
            add_to_log("#####> called from: " + backtrace);
            
        }else{
            //log("######> We are in a bad case!!!!  context pc = " + context.pc + " Base is " + baseAddress);
        }
        
    } catch (e) {
        add_to_log("Backtrace error : " + e.stack);
    }
    add_to_log("---->method entered END OF STEPS");
    
    /*--const operatorDelete: any = new NativeFunction(
    dlsym(libcpp ,"_ZdlPv")  ,
    "void",
    ["pointer"],
    {
        exceptions: ExceptionsBehavior.Propagate
    });






const findMethodForProxy: any = new NativeFunction(
    dlsym(artlib,"_ZN3art11ClassLinker18FindMethodForProxyEPNS_9ArtMethodE"),
    "pointer",
    ["pointer","pointer"],
    {
        exceptions: ExceptionsBehavior.Propagate
    }); 
const runtimeAttachCurrentThread: any = new NativeFunction(
    dlsym(artlib,"_ZN3art7Runtime19AttachCurrentThreadEPKcbP8_jobjectb"),
    "bool",
    ["pointer","bool","pointer","bool"],
    {
        exceptions: ExceptionsBehavior.Propagate
    }); 

const fopen: any = new NativeFunction(
    dlsym(libc,"fopen"),
    "pointer",
    ["pointer","pointer"],
    {
        exceptions: ExceptionsBehavior.Propagate
    });
const fprintf: any = new NativeFunction(
    dlsym(libc,"fprintf"),
    "int",
    ["pointer","pointer",'...'],
    {
        exceptions: ExceptionsBehavior.Propagate
    });
const fclose: any = new NativeFunction(
    dlsym(libc,"fclose"),
    "int",
    ["pointer"],
    {
        exceptions: ExceptionsBehavior.Propagate
    });
            

 --*/
    //LOGGING AND TESTING THREAD ID
     /*threads.forEach(function (thread) {
            let current_thread_id = Process.getCurrentThreadId();
            add_to_log('testing the thread ' + thread.id);   
            add_to_log('current thread ' + current_thread_id);  
            if( current_thread_id == thread.id){
                add_to_log("this thread is correct !! ");
                mainThread = thread;
            }
        });
    // CALLING THE BACKTRACE
        /*Thread.sleep(0.5);
        add_to_log("#####>before calling backtrace context " + JSON.stringify(mainThread_3.context));
        let backtrace = Thread.backtrace(mainThread_3.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join("\n\t#####>");
        add_to_log("#####> called from: " + backtrace);
    
    //Following the thread with the Stalker to activate the probe added in the frida thread during initialisation
          add_to_log("---------------------------->  following the current thread with the stalker thread id :" + Process.getCurrentThreadId());
        /*Stalker.follow(Process.getCurrentThreadId(), {
            events:{
                call:true
            }
        });
        add_to_log("----------------------------> end following the current thread with the stalker");
    // INSTALLING PROBE OF THE STALKER AFTER CREATING THE LISTENER CALLBACK
     add_to_log("----------------------------> Patching callback using stalker");         
    var my_callprobe = Stalker.addCallProbe(callback, function (this: InvocationContext, args: NativePointer[]): void {
        add_to_log('------------------- In the stalker : method  callback---- ' );
        add_to_log('------------------- printing the context ' + this);
    });
    add_to_log("----------------------------> callback Patched using stalker");
     ////////////// FUNCTION REVERSED TO GET THE SHORTY ON ARM64
     artQuickGenericJniTrampoline0x7371eeed00
01-18 17:14:23.313 25029 25102 I frida   : standalone: ---------------------------> printing the simple asm
01-18 17:14:23.313 25029 25102 I frida   : standalone: 0x7371eeed00--> ......... sub sp, sp, #0x120
01-18 17:14:23.313 25029 25102 I frida   : standalone: 0x7371eeed04--> ......... stp x28, x25, [sp, #0xd0]
01-18 17:14:23.313 25029 25102 I frida   : standalone: 0x7371eeed08--> ......... stp x24, x23, [sp, #0xe0]
01-18 17:14:23.313 25029 25102 I frida   : standalone: 0x7371eeed0c--> ......... stp x22, x21, [sp, #0xf0]
01-18 17:14:23.313 25029 25102 I frida   : standalone: 0x7371eeed10--> ......... stp x20, x19, [sp, #0x100]
01-18 17:14:23.313 25029 25102 I frida   : standalone: 0x7371eeed14--> ......... stp x29, x30, [sp, #0x110]
01-18 17:14:23.313 25029 25102 I frida   : standalone: 0x7371eeed18--> ......... add x29, sp, #0x110
01-18 17:14:23.313 25029 25102 I frida   : standalone: 0x7371eeed1c--> ......... mrs x8, tpidr_el0
01-18 17:14:23.313 25029 25102 I frida   : standalone: 0x7371eeed20--> ......... ldr x8, [x8, #0x28]
01-18 17:14:23.313 25029 25102 I frida   : standalone: 0x7371eeed24--> ......... adrp x9, #0x7371fe8000
01-18 17:14:23.313 25029 25102 I frida   : standalone: 0x7371eeed28--> ......... ldr x9, [x9, #0x2e0]
01-18 17:14:23.313 25029 25102 I frida   : standalone: 0x7371eeed2c--> ......... mov x23, x1   ----------------------------x23 = art_method
01-18 17:14:23.313 25029 25102 I frida   : standalone: 0x7371eeed30--> ......... stur x8, [x29, #-0x48] 
01-18 17:14:23.313 25029 25102 I frida   : standalone: 0x7371eeed34--> ......... str x23, [sp, #8]
01-18 17:14:23.313 25029 25102 I frida   : standalone: 0x7371eeed38--> ......... ldr x8, [x9]  --------------------------- x8 = runtime_object (see function retriving_rutime_object())
01-18 17:14:23.313 25029 25102 I frida   : standalone: 0x7371eeed3c--> ......... ldr x20, [x23] -------------------------- x20 = callee (in the source code, it is the current method object)
01-18 17:14:23.314 25029 25102 I frida   : standalone: 0x7371eeed40--> ......... mov x19, x0 
01-18 17:14:23.314 25029 25102 I frida   : standalone: 0x7371eeed44--> ......... ldr x8, [x8, #0x10]
01-18 17:14:23.314 25029 25102 I frida   : standalone: 0x7371eeed48--> ......... str x8, [x23]
01-18 17:14:23.314 25029 25102 I frida   : standalone: 0x7371eeed4c--> ......... str x23, [x19, #0x98]
01-18 17:14:23.314 25029 25102 I frida   : standalone: 0x7371eeed50--> ......... ldr w8, [x20, #4]------------------------ w8 = method.access_flag_obsolete
01-18 17:14:23.314 25029 25102 I frida   : standalone: 0x7371eeed54--> ......... tbnz w8, #0x12, #0x7371eeefb8
01-18 17:14:23.314 25029 25102 I frida   : standalone: 0x7371eeed58--> ......... ldr w8, [x20]---------------------------- w8 = method->declaring_class
01-18 17:14:23.314 25029 25102 I frida   : standalone: 0x7371eeed5c--> ......... ldr w0, [x8, #0x10]---------------------- w0 = x8->dexcache = method-> declaring_class -> dexcache
01-18 17:14:23.314 25029 25102 I frida   : standalone: 0x7371eeed60--> ......... ldr x8, [x0, #0x10] --------------------- x8 = x0-> dexfile = w0->dexfile =  method-> declaring_class -> dexcache-> dexfile
01-18 17:14:23.314 25029 25102 I frida   : standalone: 0x7371eeed64--> ......... ldr w9, [x20, #0xc] --------------------- w9 = x20->dex_method_index = callee->dex_method_index
01-18 17:14:23.314 25029 25102 I frida   : standalone: 0x7371eeed68--> ......... ldp x10, x11, [x8, #0x60]---------------- x10 = dexfile->method_ids ; ----- x11 = dexfile->proto_ids
01-18 17:14:23.314 25029 25102 I frida   : standalone: 0x7371eeed6c--> ......... add x9, x10, x9, lsl #3 ----------------- x9 = x10 + 8 * x9 = method_ids  + 8 * dex_method_index = method_id
01-18 17:14:23.314 25029 25102 I frida   : standalone: 0x7371eeed70--> ......... ldrh w9, [x9, #2] ----------------------- w9 = x9->proto_idx = method_id->proto_idx
01-18 17:14:23.314 25029 25102 I frida   : standalone: 0x7371eeed74--> ......... orr w10, wzr, #0xc ---------------------- w10  = 12
01-18 17:14:23.314 25029 25102 I frida   : standalone: 0x7371eeed78--> ......... mul x9, x9, x10 ------------------------- x9 = 12 * x9 = 12 * proto_idx
01-18 17:14:23.314 25029 25102 I frida   : standalone: 0x7371eeed7c--> ......... ldr w9, [x11, x9] ----------------------- w9 = content of (x11 + x9) = content of ( Protoids + 12 *  proto_idx )  = content of (proto_id) = shtoryidx (it is the first element)
01-18 17:14:23.314 25029 25102 I frida   : standalone: 0x7371eeed80--> ......... cmn w9, #1
01-18 17:14:23.314 25029 25102 I frida   : standalone: 0x7371eeed84--> ......... b.eq #0x7371eeedc0
01-18 17:14:23.314 25029 25102 I frida   : standalone: 0x7371eeed88--> ......... ldr x10, [x8, #0x48]--------------------- x10 = x8->srtring_ids = dexfile -> string_ids 
01-18 17:14:23.314 25029 25102 I frida   : standalone: 0x7371eeed8c--> ......... ldr x8, [x8, #8]------------------------- x8 = x8->dexfile_begin = dexfile_begin_address
01-18 17:14:23.314 25029 25102 I frida   : standalone: 0x7371eeed90--> ......... ldr w9, [x10, x9, lsl #2]---------------- w9 = content of (x10 + x9 * 8) = content of( string_ids + shtoryidx * 8)  = content_of (shorty_id) = proto_string_offset
01-18 17:14:23.314 25029 25102 I frida   : standalone: 0x7371eeed94--> ......... add x8, x8, x9 -------------------------- x8 = x8 + x9 = x8 + W9 = dexfile_begin + proto_offset = proto_absolute_offset
01-18 17:14:23.314 25029 25102 I frida   : standalone: 0x7371eeed98--> ......... mov x21, x8  ---------------------------- x21 = proto_absolute_offset
01-18 17:14:23.314 25029 25102 I frida   : standalone: 0x7371eeed9c--> ......... ldrsb w9, [x21], #1 -------------------- w9 = first_char_of_the_prototype....... 
01-18 17:14:23.314 25029 25102 I frida   : standalone: 0x7371eeeda0--> ......... and w25, w9, #0xff
01-18 17:14:23.314 25029 25102 I frida   : standalone: 0x7371eeeda4--> ......... tbz w9, #0x1f, #0x7371eeedc8
01-18 17:14:23.314 25029 25102 I frida   : standalone: 0x7371eeeda8--> ......... ldrsb w9, [x8, #1]
01-18 17:14:23.314 25029 25102 I frida   : standalone: 0x7371eeedac--> ......... and w25, w25, #0x7f
01-18 17:14:23.314 25029 25102 I frida   : standalone: 0x7371eeedb0--> ......... bfi w25, w9, #7, #7
01-18 17:14:23.314 25029 25102 I frida   : standalone: 0x7371eeedb4--> ......... tbnz w9, #0x1f, #0x7371eeefc8
01-18 17:14:23.314 25029 25102 I frida   : standalone: 0x7371eeedb8--> ......... add x21, x8, #2
01-18 17:14:23.314 25029 25102 I frida   : standalone: 0x7371eeedbc--> ......... b #0x7371eeedc8
01-18 17:14:23.314 25029 25102 I frida   : standalone: 0x7371eeedc0--> ......... mov w25, wzr
01-18 17:14:23.315 25029 25102 I frida   : standalone: 0x7371eeedc4--> ......... mov x21, xzr
01-18 17:14:23.315 25029 25102 I frida   : standalone: ----------------------------> end printing simple asm
//finally used /*
......... mov x23, x1   ----------------------------x23 = art_method_add
......... ldr x8, [x9]  --------------------------- x8 = runtime_object (see function retriving_rutime_object())
......... ldr x20, [x23] -------------------------- x20 = callee (in the source code, it is the current method object)
 ......... ldr w8, [x20]---------------------------- w8 = method->declaring_class
......... ldr w0, [x8, #0x10]---------------------- w0 = x8->dexcache = method-> declaring_class -> dexcache
......... ldr x8, [x0, #0x10] --------------------- x8 = x0-> dexfile = w0->dexfile =  method-> declaring_class -> dexcache-> dexfile
......... ldr w9, [x20, #0xc] --------------------- w9 = x20->dex_method_index = callee->dex_method_index
......... ldp x10, x11, [x8, #0x60]---------------- x10 = dexfile->method_ids ; ----- x11 = dexfile->proto_ids
......... add x9, x10, x9, lsl #3 ----------------- x9 = x10 + 8 * x9 = method_ids  + 8 * dex_method_index = method_id
......... ldrh w9, [x9, #2] ----------------------- w9 = x9->proto_idx = method_id->proto_idx
......... orr w10, wzr, #0xc ---------------------- w10  = 12
......... mul x9, x9, x10 ------------------------- x9 = 12 * x9 = 12 * proto_idx
......... ldr w9, [x11, x9] ----------------------- w9 = content of (x11 + x9) = content of ( Protoids + 12 *  proto_idx )  = content of (proto_id) = shtoryidx (it is the first element)
......... ldr x10, [x8, #0x48]--------------------- x10 = x8->srtring_ids = dexfile -> string_ids 
......... ldr x8, [x8, #8]------------------------- x8 = x8->dexfile_begin = dexfile_begin_address
......... ldr w9, [x10, x9, lsl #2]---------------- w9 = content of (x10 + x9 * 8) = content of( string_ids + shtoryidx * 8)  = content_of (shorty_id) = proto_string_offset
......... add x8, x8, x9 -------------------------- x8 = x8 + x9 = x8 + W9 = dexfile_begin + proto_offset = proto_absolute_offset
......... mov x21, x8  ---------------------------- x21 = proto_absolute_offset
......... ldrsb w9, [x21], #1 -------------------- w9 = first_char_of_the_prototype....... 
......... and w25, w9, #0xff
*/
        

