<?php
/**
 * @author BytePhunk bytephunk.wordpress.com, github.com/bytephunk
 * 
 * Basic websocket protocol frame encoding/decoding according to the rfc6455 specifications. 
 * Namely these functions encode/decode dataframes in use AFTER the protocol handshake. No protocol extensions included nor checkup for data integrity and protocol observance.
 * 
 * Documentation about protocol specifics can be found at https://tools.ietf.org/html/rfc6455
 */ 
namespace BytePhunk\Websockets;

/**
 * Encoding of data according to rfc6455 specifications. 
 * 
 * @param string $payload 
 * @param int $opcode. Defaults to text payload.
 * @param bool $fin if the frame is final
 * @param bool $mask according to protocol rules the frame should be always unmasked when sent by the server. The function, however provides the capacity for masking frames.
 * @return string
 */
function frameEncode(string $payload,int $opcode=1,bool $fin=true,bool $mask=false){
    $first=0;
    $first  |= $fin?128:0;      //set final
    $first  |= ($opcode & 15);   //restrain opcode to the first 4 bits anyway.
    
    $length=strlen($payload);
    
    $second=0;
    $second |= $mask?128:0;     //set mask
    if($length <=125 ){
        $headerLength=2;
        $second |= $length;
    }
    elseif($length < (2**16)) {//fits in 2 bytes
        $headerLength=4;
        $second |= 126;
        $extraLength=pack("n",$length);
    }
    else {
        $headerLength=10;
        $second |= 127;
        $extraLength=pack("J",$length);
    }
    $header =chr($first).chr($second);
    $header.= $extraLength??""; 
    
    if($mask){
        $mask=openssl_random_pseudo_bytes(4);
       
        if(!$mask) throw new Exception("Can't generate random mask");
        $header.=$mask;
        $payloadArr =str_split($payload);
        $maskArr    =str_split($mask);
        for($i=0;$i<$length;$i++){
            $m=$maskArr[$i % 4];
   
            $payloadArr[$i] ^= $m;
        }
        
        $payload=implode("",$payloadArr);
    }
    return $header.$payload;
}

/**
 * Decoding of data according to rfc6455 specifications.
 * @note no error message will be triggered if the protocol is broken: e.g. the client sends unmasked frames.
 * @param string $frame the raw frame 
 * @param array $frameArr return array containing the frame data
 * @return string the payload 
 */
function frameDecode(string $frame,&$frameArr){
    
    $f=array_values(unpack("C*",$frame));

    //first byte
    $fin = (bool) ($f[0] & 128 );
    $rsv1= (bool) ($f[0] & 64  );
    $rsv2= (bool) ($f[0] & 32  );
    $rsv3= (bool) ($f[0] & 16  );
    $opcode= $f[0]  & 15;

    //second byte
    $hasmask=(bool) ($f[1] & 128) ; // mask value on 1 bit
    $primaryLength=$f[1] & 127; //primary length value on 7 bits
    
    //compute length
    if($primaryLength<=125){
        $headerLength=2;
        $length=$primaryLength;
    }
    elseif( $primaryLength==126){
        $headerLength=4;
        $length=unpack("nhead/nlength",$frame)['length'];//unpack as big endian 16 bit
        
    }
    elseif ($primaryLength==127){
        $headerLength=10;
        $length=unpack("nhead/Jlength",$frame)['length'];//upack as big endian 64 bit 
    }

    $payloadOffset=$hasmask?$headerLength+4:$headerLength;
    
    
        
    //Without extensions involved, there shouldn't be anything beyond the payload inside the frame, however we limit the array slice to $length.
    $payload=array_slice($f,$payloadOffset,$length);

    if ($hasmask)
    {
        $mask= array_slice($f,$headerLength,4);
        $i=0;
        foreach($payload as &$chr){
            
            $m=$mask[$i % 4];
            $chr= chr($chr ^ $m); //unmask
            $i++;
        }
    }
    else{
        foreach ($payload as &$chr)
                    $chr = chr($chr); //turn int to character
    }
    
    
    $frameArr=compact('fin','rsv1','rsv2','rsv3','length','hasmask','opcode','payloadOffset','headerLength');
    
    return implode("",$payload);
}