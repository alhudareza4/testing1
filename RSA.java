import java.math.BigInteger; 
import java.security.*; 
import java.util.Base64; 
import javax.crypto.BadPaddingException; 
import javax.crypto.Cipher; 
import javax.crypto.IllegalBlockSizeException; 
import javax.crypto.NoSuchPaddingException; 

public class RSA 
    {    
        private KeyPairGenerator kpg;  
        private KeyPair kp;  
        private PublicKey publicKey;  
        private PrivateKey privateKey;    
        private byte[] publicKeyByte;  
        private byte[] privateKeyByte;    
        private String publicKeyString;  
        private String privateKeyString; 
        
        // The input (2)  
        private String message = "Man is a slow, sloppy, and brilliant thinker; computers are fast, accurate, and stupid.";
        // This is method is used to generate a public-private key of RSA. It will print  
        // the public and private key generated from this method afterwards.
        
        public void generateKeyPair()
            {   
                try{ 
                    // Get the RSA object and specifying the RSA algorithm    
                    KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");    
                    // Initialize the key pair generator with the size of 2048 bits    
                    kpg.initialize(2048); 
                    // Generate the key pair    
                    kp = kpg.genKeyPair();    
                    // Get the public key from the generated key    
                    publicKey = kp.getPublic();    
                    // Get the private key from the generated key    
                    privateKey = kp.getPrivate(); 
                    // Get the bytes from the public key    
                    publicKeyByte = publicKey.getEncoded();    
                    // Get the bytes from the private key    
                    privateKeyByte = privateKey.getEncoded(); 
                    // Convert the public key bytes into String    
                    publicKeyString = Base64.getEncoder().encodeToString(publicKeyByte);    
                    // Convert the private key bytes into String    
                    privateKeyString = Base64.getEncoder().encodeToString(privateKeyByte);
                    System.out.println("public key : \n" + publicKeyString);    
                    System.out.println("\nprivate key : \n" + privateKeyString);    
                    System.out.println("\n"); 
                    }   
                    catch(NoSuchAlgorithmException e)
                        {    
                            System.out.println(e);   
                        }  
                    }
                    
                    //This is method is used to encrypt the message using the RSA public key.
                    public byte[] encrypt(String data, PublicKey publicKey)
                    {   
                        try{    
                            // Get the Cipher instance and specifying the algorithm.    
                            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");    
                            // Initialize the cipher with the encryption mode and public key    
                            cipher.init(Cipher.ENCRYPT_MODE, publicKey); 
                            
                            return cipher.doFinal(data.getBytes());   
                        }
                        
                        catch(BadPaddingException | IllegalBlockSizeException | InvalidKeyException | NoSuchPaddingException | NoSuchAlgorithmException e)
                        {    
                            System.out.println(e);    
                            return null;   
                        }  
                    }
                    
                    // This is method is used to decrypt the message using the RSA private key. 
                    public String decrypt(byte[] data, PrivateKey privateKey) throws NoSuchPaddingException,     NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException 
                     {   
                         // Get the Cipher instance and specifying the algorithm.      
                         Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");      
                         // Initialize the cipher with the decryption mode and private key        
                         cipher.init(Cipher.DECRYPT_MODE, privateKey); 
                         return new String(cipher.doFinal(data));    
                     } 
                     // This is method is used to decrypt the message using the RSA private key.  
                     // This method is only used to call the decrypt method that does the real work.  
                     // The reason is to simplify the code by converting the input into bytes. 
                     public String decrypt(String data, PrivateKey privateKey) throws IllegalBlockSizeException, InvalidKeyException,     BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException 
                      {        
                          return decrypt(Base64.getDecoder().decode(data.getBytes()), privateKey);    
                      }
                      //This is the main method which makes use of the encrypt and decrypt methods from the RSA object.  
                      public static void main(String args[]) 
                      {   
                          RSA te = new RSA();   
                          te.generateKeyPair();   
                          try { 
                              System.out.println("Encrypted String : ");         
                              // Encrypt the string         
                              String encryptedString = Base64.getEncoder().encodeToString(te.encrypt(te.message, te.publicKey)); 
                              // Print out the encrypted string         
                              System.out.println(encryptedString + "\n"); 
                              System.out.println("Decrypted String : ");    
                              // Decrypt the encrypted string 
                              String decryptedString = te.decrypt(encryptedString, te.privateKey);         
                              // Print out the decrypted string         
                              System.out.println(decryptedString); 
                              }    catch (Exception e) 
                                {         
                                    System.err.println("");      
                                } 
                                } 
                      }
 