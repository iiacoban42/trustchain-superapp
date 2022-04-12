package nl.tudelft.trustchain.frost

import android.os.Bundle
import android.text.method.ScrollingMovementMethod
import android.util.Log
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.TextView
import kotlinx.android.synthetic.main.fragment_frost.*
import nl.tudelft.trustchain.common.ui.BaseFragment
import nl.tudelft.trustchain.common.util.viewBinding
import nl.tudelft.trustchain.frost.databinding.FragmentFrostBinding


class FrostFragment : BaseFragment(R.layout.fragment_frost) {
    private val binding by viewBinding(FragmentFrostBinding::bind)

    private fun getFrostCommunity(): FrostCommunity {
        return getIpv8().getOverlay()
            ?: throw java.lang.IllegalStateException("FROSTCommunity is not configured")
    }

    override fun onActivityCreated(savedInstanceState: Bundle?) {
        super.onActivityCreated(savedInstanceState)
        text_button_3.movementMethod = ScrollingMovementMethod()
        initClickListeners()
        writeToFile(this.context, "acks.txt", "")
        writeToFile(this.context, "received_shares.txt", "")
    }

    override fun onCreateView(
        inflater: LayoutInflater, container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View? {
        // Inflate the layout for this fragment
        return inflater.inflate(R.layout.fragment_frost, container, false)
    }

    /**
     * Utility method for changing the text inside a textView.
     */
    private fun changeText(textView: TextView, text: String){
        textView.text = text
    }

    /**
     * Initiate the click listeners for the buttons.
     */
    private fun initClickListeners() {

        // create signer
        button1.setOnClickListener {
            changeText(text_button_1, "Press \"REFRESH\" to check received acks or shares")
            changeText(text_button_3, "")
            changeText(text_button_4, "")
            writeToFile(this.context, "acks.txt", "")
            writeToFile(this.context, "received_shares.txt", "")
            getFrostCommunity().createSigner(THRESHOLD, false)
        }
        // distribute shares
        button2.setOnClickListener {
            changeText(text_button_2, "")
            getFrostCommunity().createShares()
        }
        // view who sent key shares
        button3.setOnClickListener {
            changeText(text_button_3, "")
            val signers = getFrostCommunity().getSignersWithKeys()
            Log.i("FROST", signers)
            changeText(text_button_3, "Known signers/keys: \n $signers")
        }
        // view who acked my key shares
        button4.setOnClickListener {
            changeText(text_button_4, "")
            val shares = readFile(this.context, "received_shares.txt")
            val text = "$shares"
            Log.i("FROST", text)
            changeText(text_button_4, "Received shares from: \n $text")
        }
        // call receive frost
        button5.setOnClickListener {
            Log.i("FROST", "FROST received")
            getFrostCommunity().receiveFrost()
            changeText(text_button_5, "FrostDone")

        }
    }
}
