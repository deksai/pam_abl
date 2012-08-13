<?php include("./head") ?>
<div class="post">
	<h2 class="title"><a href="#">What is PAM ABL?</a></h2>
	<div style="clear: both;">&nbsp;</div>
	<div class="entry">
		<p>
		pam_abl is a pam module designed to
		automatically block hosts which are attempting
		a brute force attack.  Brute force attacks are
		an unsophisticated way to find authentication
		credentials.  Basically, a computer is setup to
		try all kinds of user names and password
		combinations until one works.  It may sound
		fairly far fetched, but it does actually work.
		Many system accounts have common user names.
		Passwords are also easily guessable in many
		situations.
		</p>
		<p>
		pam_abl is able to protect any service which
		uses it for authentication.  It works on the
		assumption that an attacker won't get the
		password right without a lot of trying.  It
		watches for attacks by counting how many times
		a certain user or host tries to log into the
		service unsuccessfully.  the host or user name
		is recorded along with the service being
		attacked.  Optionally, the system can also run
		user defined scripts when this happens, like
		updating a firewall etc.  After that point, it
		will be impossible for that user or host to
		successfully log in.  The attacker can keep
		trying as much as he wants, but will never find
		a way to login with his current method. 
		</p>
		<p>
		After a configured amount of time without any
		attempts, the user account or remote host will
		be allowed to log in again.  When this happens,
		there is another opportunity to run system
		commands.
		</p>
		<h3>Command line interface</h3>
		<p>
		Although pam_abl is a PAM module, you can also
		use it in applications that are not PAM enabled
		(eg. an FTP server using a custom
		authentication method to validate virtual
		users).  For these situations, there is a also
		a command line (scriptable) interface to all
		the data in the database.  This allows sharing
		of authentication failure data between PAM
		applications and non-PAM applications.  It
		makes it fairly easy for a system administrator
		to manage or manipluate the system.  
		</p>
		<p class="links"><a href="docs.php">Read More</a>
		</p>
	</div>
	</div>
<div style="clear: both;">&nbsp;</div>
</div>
		<!-- end #content -->
<?php include("./footer") ?>
