package nl.tudelft.trustchain.frost

import android.content.Context
import android.util.Log
import bitcoin.*
import bitcoin.Secp256k1Context.*
import nl.tudelft.ipv8.Community
import nl.tudelft.ipv8.Overlay
import nl.tudelft.ipv8.Peer
import nl.tudelft.ipv8.keyvault.PrivateKey
import nl.tudelft.ipv8.messaging.Packet
import kotlin.random.Random

val THRESHOLD = 2

class FrostCommunity(private val context: Context,
                     private var signers: MutableList<FrostSigner>,
                     private var keyShares: MutableMap<Int, ByteArray>,
                     private var secret: FrostSecret
): Community(){
    override val serviceId = "98c1f6342f30528ada9647197f0503d48db9c2fb"

    init {
        messageHandlers[MessageId.SEND_KEY] = ::onDistributeShares
        messageHandlers[MessageId.ACK_KEY] = ::onAckKey
        messageHandlers[MessageId.SEND_SIGNER] = ::onCreateSigner
    }
    override fun load() {
        super.load()

        if (Random.nextInt(0, 1) == 0) initiateWalkingModel()
    }

    fun getKeyshares(): MutableMap<Int, ByteArray> {
        return this.keyShares
    }

    fun getSigners(): MutableList<FrostSigner> {
        return this.signers
    }
    /**
     * Load / create walking models (feature based and collaborative filtering)
     */
    private fun initiateWalkingModel() {
        try {
            Log.i("FROST", "Initiate random walk")
        } catch (e: Exception) {
            Log.i("FROST", "Random walk failed")
            e.printStackTrace()
        }
    }

    /**
     * Create a signer for this user and broadcast it to the network.
     *
     * @param threshold: the threshold for the Schnorr signature
     * @param sendBack: boolean used to determine if we should send
     *                  back the signer that this user creates
     */
    fun createSigner(threshold: Int, sendBack: Boolean) {
        // set own ip address
        myPeer.address = myEstimatedWan
        // only create a new signer if there is not already one
        if (!signerInList(myPeer.address.ip)) {
            Log.i("FROST", "${myPeer.address} creating own signer")
            // add self as signer
            val signer = FrostSigner(threshold)
            val secret = FrostSecret()
            // generate the public and private keys
            NativeSecp256k1.generateKey(secret, signer)
            this.secret = secret
            signer.ip = myPeer.address.ip
            // add the newly created signer to the list
            // (so we don't create new ones for this same user in the future)
            this.signers.add(signer)

            // loop over all peers except this user
            for (peer in getPeers()) {
                if (peer != myPeer) {
                    // serialize the packet so ipv8 can send it
                    val packet = serializePacket(
                        MessageId.SEND_SIGNER,
                        FrostSignerPacket(
                            signer.pubkey,
                            signer.pubnonce,
                            signer.partial_sig,
                            signer.vss_hash,
                            signer.pubcoeff
                        ),
                        encrypt = true,
                        sign = true,
                        recipient = peer
                    )
                    // when sendBack is true, send the message to the peer
                    if (sendBack){
                        Log.i("FROST", "${myPeer.address} sending signer to ${peer.address}")
                        send(peer, packet)
                    }
                    // when sendBack is false, send the message only if we haven't received
                    // a signer from the peer we're trying to send to
                    else if (!signerInList(peer.address.ip)) {
                        Log.i("FROST", "${myPeer.address} sending signer to ${peer.address}")
                        send(peer, packet)
                    }
                }
            }
        }
    }

    /**
     * Pairs with createSigner, but is called when receiving
     * a message sent by the createSigner function.
     */
    fun onCreateSigner(packet: Packet) {
        val (peer, payload) = packet.getDecryptedAuthPayload(FrostSignerPacket.Deserializer, myPeer.key as PrivateKey)
        val signer = FrostSigner(
            payload.pubkey,
            payload.pubnonce,
            payload.partial_sig,
            payload.vss_hash,
            payload.pubcoeff
        )

        Log.i("FROST DESERIALIZER", "pubcoeffarray ${payload.pubcoeff}")


        for (arr in payload.pubcoeff) {
            Log.i("FROST DESERIALIZER", "bytearray ${arr}")
            for(el in arr) {
                Log.i("FROST DESERIALIZER", "element ${el}")
            }
        }


        signer.ip = peer.address.ip

        Log.i("FROST", "${myPeer.address} received signer from ${peer.address}")

        // check if we received a signer from an ip that we haven't previously received a signer from
        if(!signerInList(peer.address.ip)){
            Log.i("FROST", "${myPeer.address} signer was unknown, adding to list")
            // add the signer to the list of known signers
            // (call this user1, the one who initiated the protocol)
            this.signers.add(signer)
            // call createSigner to create this user's (user2) signer
            // and set sendBack to true, to make sure that we also send
            // the new signer back to user1 and not just
            // to the other peers who are not in the list yet
            createSigner(THRESHOLD, true)
        }
        else
            // if we have already received a signer from user1,
            // log this and move on
            Log.i("FROST", "${myPeer.address} signer was known")
    }

    /**
     * Creates the shares that need to be distributed to the known signers.
     */
    fun createShares(){
        // sort the signers list so that everyone has the same order for the signers
        this.signers.sort()
        val i = getIndexOfSigner(myPeer.address.ip)

        val res = NativeSecp256k1.sendShares(getPublicKeysFromSigners(), this.secret, this.signers[i])

        // create a list of all peers
        val list = mutableListOf<Peer>()
        for(signer in this.signers){
            val peerAddress = signer.ip
            list.add(getPeerFromIP(peerAddress)!!)
        }

        // loop over res and distribute the shares
        for(share in res){
            // call distributeShares to send the created shares one by one
            distributeShares(share, list)
        }
    }

    /**
     * Helper function for createShares().
     * Distributes the key shares created by createShares().
     */
    private fun distributeShares(
        keyShare: ByteArray,
        peers: List<Peer>? = null
    ){
        // input sanity check
        var peerList = peers
        if(peerList == null){
            peerList = getPeers()
        }

        // loop over the peerList (including self) and send each peer this share
        for (peer in peerList) {
            if(peer == myPeer){
                val i = getIndexOfSigner(myPeer.address.ip)
                this.keyShares[i] = keyShare
            }
            val packet = serializePacket(
                MessageId.SEND_KEY,
                KeyPacketMessage(keyShare),
                encrypt = true,
                sign = true,
                recipient = peer
            )
            Log.i("FROST", "${myPeer.address} sending key share to ${peer.address}")
            send(peer, packet)
        }
    }

    /**
     * Pairs with distributeShares, but is called when receiving
     * a message sent by the distributeShares function.
     */
    private fun onDistributeShares(packet: Packet) {
        Log.i("FROST", "Key packet received $packet")
        val (peer, payload) = packet.getDecryptedAuthPayload(KeyPacketMessage.Deserializer, myPeer.key as PrivateKey)
        val keyShare = payload.keyShare
        val i = getIndexOfSigner(peer.address.ip)

        // add the received key share to the list of key shares
        this.keyShares[i] = keyShare

        // also add to a local file which is used when printing
        val ackBuffer = readFile(this.context,"received_shares.txt")

        // remove duplicates (since we also send the shares to ourselves)
        val splitList = ackBuffer?.split("\n")
        var list = splitList?.toTypedArray()
        list = list?.plus("${peer.address}")
        val uniqueList = list?.toSet()?.toList()
        val uniqueBuffer = uniqueList?.joinToString("\n")

        if (uniqueBuffer != null) {
            writeToFile(this.context, "received_shares.txt", "$uniqueBuffer")
        }

        // confirm that the received key share arrived
        ackKey(peer, keyShare)

        Log.i("FROST", "Key fragment acked $keyShare")
    }

    /**
     * Function for acknowledging a key,called when receiving
     * a key share that needs to be acknowledged.
     */
    private fun ackKey(peer: Peer, keyShare: ByteArray){
        val ack = serializePacket(
            MessageId.ACK_KEY,
            Ack(keyShare),
            encrypt = true,
            sign = true,
            recipient = peer
        )
        Log.i("FROST", " ${myPeer.address} sending key ack to ${peer.address}")
        send(peer, ack)
    }

    /**
     * Pairs with ackKey, but is called when receiving
     * a message sent by the ackKey function.
     */
    private fun onAckKey(packet: Packet){
        val (peer, payload) = packet.getDecryptedAuthPayload(Ack.Deserializer, myPeer.key as PrivateKey)
        Log.i("FROST", "${myPeer.address} acked key ${payload.keyShare} from ${peer.address}")
        val ackBuffer = readFile(this.context,"acks.txt")
        val newBuffer = "$ackBuffer \n ${peer.address}"
        writeToFile(this.context, "acks.txt", newBuffer)
    }

    /**
     * Call receiveFrost.
     * !! This does not work yet!!
     */
    fun receiveFrost(){
        val i = getIndexOfSigner(myPeer.address.ip)
        // check that context is enabled
        if(isEnabled()){

            NativeSecp256k1.receiveFrost(arrayOf(this.keyShares[i]), this.secret, this.signers.toTypedArray(), i)
        }
    }

    /**
     * Utility function for checking if a signer is already
     * known, by checking if its ip is in the list.
     */
    private fun signerInList(ip: String): Boolean {
        for (signer in signers){
            if(ip == signer.ip){
                return true
            }
        }
        return false
    }

    /**
     * Utility function for getting the list id of the
     * signer that corresponds to the given ip.
     */
    private fun getIndexOfSigner(ip: String): Int{
        var i = -1
        for (signer in signers){
            i++
            if(ip == signer.ip){
                break
            }
        }
        return i
    }

    /**
     * Utility function for getting the peer
     * that corresponds to a given ip.
     */
    private fun getPeerFromIP(ip: String): Peer?{
        if (myPeer.address.ip == ip)
            return myPeer
        Log.i("FROST", " GET PEER ip: $ip ")
        for (p in getPeers()){
            Log.i("FROST", "GET PEER p.address: ${p.address} ")
            if(p.address.ip == ip){
                Log.i("FROST", "GET PEER if was true: $ip == ${p.address} ")

                return p
            }
        }
        return null
    }

    /**
     * Utility function for getting the list of known
     * public keys from all known signers
     */
    private fun getPublicKeysFromSigners(): Array<ByteArray>{
        var keys = mutableListOf<ByteArray>()
        for (signer in signers){
            keys.add(signer.pubkey)
        }
        return keys.toTypedArray()
    }

    /**
     * Utility function for getting all the known signers
     * and their corresponding keys to print on screen.
     */
    fun getSignersWithKeys(): String{
        var result = ""
        for (signer in this.signers){
            val element = "ip: ${signer.ip} - key: ${signer.pubkey.contentToString()}"
            result = "$result \n\n $element"
        }
        return result
    }

    object MessageId {
        const val SEND_KEY = 0
        const val ACK_KEY = 1
        const val SEND_SIGNER = 2
    }

    class Factory(
        private val context: Context,
        private val signers: MutableList<FrostSigner>,
        private val keyShares: Map<Int, ByteArray>,
        private val secret: FrostSecret
    ) : Overlay.Factory<FrostCommunity>(FrostCommunity::class.java) {
        override fun create(): FrostCommunity {
            return FrostCommunity(context, signers, keyShares as MutableMap<Int, ByteArray>, secret)
        }
    }
}

