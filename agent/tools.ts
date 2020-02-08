import { log } from "./logger";


export class MethodInfoDecryptage { //this object is passed to the listerner from an intercepted function in the art, called before the listener, it contains usefull infomations 
                                            // to decrytp arguments passed to the method, like the code_item and the shadow frame. 
    code_item: NativePointer;
    shadow_frame: NativePointer;
    /*constructor() {    
        this.handle = Memory.alloc(3 * Process.pointerSize);
    }*/
    constructor()
    constructor(code_item_: NativePointer, shadow_frame_: NativePointer) 
    constructor(code_item_?: NativePointer, shadow_frame_?: NativePointer)  {    
        if(code_item_ != null){
            this.code_item = code_item_;
        }else{
            this.code_item = Memory.alloc(Process.pointerSize);;
        }
        if(shadow_frame_ != null){
            this.shadow_frame = shadow_frame_;
        }else{
            this.shadow_frame = Memory.alloc(Process.pointerSize);;
        }
    }
}


export class Stack<T>{
    _stack: T[];
 
    constructor(stack?: T[]) {
      this._stack = stack || [];
    }
 
    push(item: T) {
      this._stack.push(item);
    }
 
    pop(): T | undefined {
      return this._stack.pop();
    }
    
    clear() {
      this._stack = [];
    }
 
    get count(): number {
      return this._stack.length;
    }
}

export class StdInstrumentationStackDeque {
    // from the class definition https://github.com/llvm-mirror/libcxx/blob/master/include/deque
    // line 959 you have three parameters 
    // to simplify we remove the private inerhitrance with deque_base
    handle: NativePointer;
    __start_ : number = 0;
    //__block_size is a const (line 945). Initialized (line 1037)
    // in the __deque_block_size struct value_type size is 20 and 
    // refferring to the line  276 it is < 256 , so we have 4096/20 =~ 204
    __block_size : number = 204; 
    constructor(handle_: NativePointer) {
        //log(" we construct the stack object"); 
        let __start_Offset  = 4*Process.pointerSize; 
        this.handle = handle_;
        this.__start_ = Memory.readUInt(handle_.add(__start_Offset));
        
    }

    // actualize other attributes at every read

    size(): number {
        // it is in the third parameter, first element of the compressed pair  https://www.boost.org/doc/libs/1_47_0/boost/detail/compressed_pair.hpp  
        let sizeOffset = 5*Process.pointerSize;
        let result = Memory.readUInt(this.handle.add(sizeOffset));  
        //log ("- size of the instrumentation queue : " + result);
        return result;
    }

    __map_begin(): NativePointer {
        // it is in  the first parameter __map_,   witch is a split_buffer 
        // https://github.com/google/libcxx/blob/master/include/__split_buffer line 47  
        let sizeOffset = 1*Process.pointerSize;
        let result = Memory.readPointer(this.handle.add(sizeOffset)); 
        //log ("- begin of the  map in instrumentation queue : " + result); 
        return result;
    }

    __map_end(): NativePointer {
        // it is in  the first parameter __map_,   witch is a split_buffer 
        // https://github.com/google/libcxx/blob/master/include/__split_buffer line 48 
        let endOffset = 2*Process.pointerSize;
        let result = Memory.readPointer(this.handle.add(endOffset));  
        //log ("- end of the map of the instrumentation queue : " + result);
        return result;
    }
    __map_empty(): boolean {
        // it is compute from   the first parameter  __map_, witch is a split_buffer 
        // https://github.com/google/libcxx/blob/master/include/__split_buffer line 85
        let result =  this.__map_end().compare(this.__map_begin()) == 0;
        //log ("- map  of the instrumentation queue  is empty: " + result);
        return result;
    }
    
    refresh(){
        let __start_Offset  = 4*Process.pointerSize; 
        this.__start_ = Memory.readUInt(this.handle.add(__start_Offset));
        //log ("- start offset in the map of the instrumentation queue : " + this.__start_);
    }
    front(): NativePointer {
        // here we don't dereference the result, it is still a pointer 
        // defined at line 1788 https://github.com/llvm-mirror/libcxx/blob/master/include/deque
        this.refresh();
        log("---  we get the front of the deque"); 
        let __p : number =  this.__start_;
        log(" value of p " + __p); 
        let  __mp : NativePointer = this.__map_begin().add(Math.floor(__p / this.__block_size) * Process.pointerSize) ;
        log (" processing the __mp : " + __mp + " with ratio p/size : " +  Math.floor(__p / this.__block_size)
                                 + " p%size = " + __p % this.__block_size);
        let result : NativePointer = Memory.readPointer(__mp).add((__p % this.__block_size) * Process.pointerSize);
        log("final result " + result );
        return result;
    } 

    back(): NativePointer {
        // here we don't dereference the result, it is still a pointer 
        // defined at line 1815 https://github.com/llvm-mirror/libcxx/blob/master/include/deque
        this.refresh();
        log("---  we get the front of the deque"); 
        let __p : number =  this.size() + this.__start_ - 1;
        log(" value of p " + __p); 
        let  __mp : NativePointer = this.__map_begin().add(Math.floor(__p / this.__block_size) * Process.pointerSize) ;
        log (" processing the __mp : " + __mp + " with ratio p/size : " +  Math.floor(__p / this.__block_size)
                                 + " p%size = " + __p % this.__block_size);
        let result : NativePointer = Memory.readPointer(__mp).add((__p % this.__block_size) * Process.pointerSize);
        log("final result " + result );
        return result;
    } 
}

export class StdString {
    handle: NativePointer;

    /*constructor() {    
        this.handle = Memory.alloc(3 * Process.pointerSize);
    }*/
    constructor()
    constructor(handle_ : NativePointer) 
    constructor(handle_? : NativePointer) {    
        if(handle_ != null){
            this.handle = handle_;
        }else{
            this.handle = Memory.alloc(3 * Process.pointerSize);
        }
    }
    dispose(): void {
        if (!this.isTiny()) {
            //operatorDelete(this.getAllocatedBuffer());
        }
    }

    read(): string {
        //log(hexdump(this.handle, { length: 12 }));
        let str: string | null = null;
        if (this.isTiny()) {
            str = Memory.readUtf8String(Memory.readPointer(this.handle.add(1 * Process.pointerSize)));  ///////////////////////////  1*Process.pointerSize
        } else {
            str = Memory.readUtf8String(this.getAllocatedBuffer());
        }
        return (str !== null) ? str : "";
    }
    
    private isTiny(): boolean {
        return (Memory.readU8(this.handle) & 1) === 0;
    }

    private getAllocatedBuffer(): NativePointer {
        return Memory.readPointer(this.handle.add(2 * Process.pointerSize));
    }
}
