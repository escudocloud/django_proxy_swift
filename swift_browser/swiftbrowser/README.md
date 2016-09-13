# encswift_client_ovenc

Encswift app can put encrypted files on swift. It introduces the Over-Encryption, in order to avoid useless change on each file, after a policy change.
In order to start this app you have to run both `start_app` and `start_rabbit` together. Moreover, a particular version of Swift has to run on the server. 

# Branches
Stable release is in branch __master__

# Features redesigned:
* `Put container ovenc`: it puts a new container and generates a key for it. The users' catalogs are automatically updated
* `Put object ovenc`: it retrieves the cipher key of the container, uses it to encrypt the object and puts it in the container
* `Get object ovenc`: it retrieves the BEL and SEL keys of the container, gets the object from the container and decrypts it.
* `Post container ovenc`: it posts new headers for a certain container (paying attention if the user tries to change the acl...). It handles the keys management, mainly from the Surface Layer point of view.

# Features used and included in the original project:
* `Create user`: it automatically creates a new Keystone user and her Escudo properties (the meta-container and the catalog)
* `Head enc container`: it retrieves the header of the enc container
* `Head enc object`: it retrieves the headers of the enc object 
* `Post enc object`: it posts new headers for an enc object
* `Delete enc container`: it deletes a container, removing its key from the catalogs of all the users in the acl, and updating the graph
* `Delete enc object`: it retrieves the cipher key of the container, encrypts the name of the object (so that it can find it) and delete it
