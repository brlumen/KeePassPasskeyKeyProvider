using System;
using System.Text;
using System.Windows.Forms;
using KeePassPasskeyKeyProvider.WebAuthn;

namespace KeePassPasskeyKeyProvider
{
	/// <summary>
	/// Form for diagnosing FIDO2 security keys and checking PRF (Pseudo-Random Function) support
	/// </summary>
	public partial class FIDO2DiagnosticsForm : Form
	{
		private TextBox txtLog;
		private Button btnTestHmacSecret;
		private Button btnCheckApiVersion;
		private Button btnClose;
		private StringBuilder logBuilder;

		public FIDO2DiagnosticsForm()
		{
			InitializeComponent();
			logBuilder = new StringBuilder();
		}

		private void InitializeComponent()
		{
			this.txtLog = new TextBox();
			this.btnTestHmacSecret = new Button();
			this.btnCheckApiVersion = new Button();
			this.btnClose = new Button();
			this.SuspendLayout();

			// txtLog
			this.txtLog.Anchor = ((AnchorStyles)((((AnchorStyles.Top | AnchorStyles.Bottom)
				| AnchorStyles.Left)
				| AnchorStyles.Right)));
			this.txtLog.Font = new System.Drawing.Font("Consolas", 9F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(204)));
			this.txtLog.Location = new System.Drawing.Point(12, 12);
			this.txtLog.Multiline = true;
			this.txtLog.Name = "txtLog";
			this.txtLog.ReadOnly = true;
			this.txtLog.ScrollBars = ScrollBars.Vertical;
			this.txtLog.Size = new System.Drawing.Size(660, 380);
			this.txtLog.TabIndex = 0;

			// btnCheckApiVersion
			this.btnCheckApiVersion.Anchor = ((AnchorStyles)((AnchorStyles.Bottom | AnchorStyles.Left)));
			this.btnCheckApiVersion.Location = new System.Drawing.Point(12, 398);
			this.btnCheckApiVersion.Name = "btnCheckApiVersion";
			this.btnCheckApiVersion.Size = new System.Drawing.Size(150, 30);
			this.btnCheckApiVersion.TabIndex = 1;
			this.btnCheckApiVersion.Text = "Check API";
			this.btnCheckApiVersion.UseVisualStyleBackColor = true;
			this.btnCheckApiVersion.Click += new EventHandler(this.BtnCheckApiVersion_Click);

			// btnTestHmacSecret
			this.btnTestHmacSecret.Anchor = ((AnchorStyles)((AnchorStyles.Bottom | AnchorStyles.Left)));
			this.btnTestHmacSecret.Location = new System.Drawing.Point(168, 398);
			this.btnTestHmacSecret.Name = "btnTestHmacSecret";
			this.btnTestHmacSecret.Size = new System.Drawing.Size(180, 30);
			this.btnTestHmacSecret.TabIndex = 2;
			this.btnTestHmacSecret.Text = "PRF test";
			this.btnTestHmacSecret.UseVisualStyleBackColor = true;
			this.btnTestHmacSecret.Click += new EventHandler(this.BtnTestHmacSecret_Click);

			// btnClose
			this.btnClose.Anchor = ((AnchorStyles)((AnchorStyles.Bottom | AnchorStyles.Right)));
			this.btnClose.Location = new System.Drawing.Point(597, 398);
			this.btnClose.Name = "btnClose";
			this.btnClose.Size = new System.Drawing.Size(75, 30);
			this.btnClose.TabIndex = 3;
			this.btnClose.Text = "Close";
			this.btnClose.UseVisualStyleBackColor = true;
			this.btnClose.Click += new EventHandler(this.BtnClose_Click);

			// FIDO2DiagnosticsForm
			this.AutoScaleDimensions = new System.Drawing.SizeF(6F, 13F);
			this.AutoScaleMode = AutoScaleMode.Font;
			this.ClientSize = new System.Drawing.Size(684, 440);
			this.Controls.Add(this.btnClose);
			this.Controls.Add(this.btnTestHmacSecret);
			this.Controls.Add(this.btnCheckApiVersion);
			this.Controls.Add(this.txtLog);
			this.MinimumSize = new System.Drawing.Size(600, 400);
			this.Name = "FIDO2DiagnosticsForm";
			this.StartPosition = FormStartPosition.CenterParent;
			this.Text = "FIDO2 Diagnostics - PRF Support Check";
			this.Load += new EventHandler(this.FIDO2DiagnosticsForm_Load);
			this.ResumeLayout(false);
			this.PerformLayout();
		}

		private void FIDO2DiagnosticsForm_Load(object sender, EventArgs e)
		{
			Log("=== FIDO2 Diagnostics - PRF Extension ===");
			Log("");
			Log("This utility helps determine whether your FIDO2 security key supports");
			Log("the PRF (Pseudo-Random Function) extension - WebAuthn Level 3.");
			Log("");
			Log("PRF is the modern replacement for hmac-secret, supported by newer keys.");
			Log("");
			Log("Steps:");
			Log("1. Click 'Check API' to check WebAuthn API availability");
			Log("2. Click 'PRF test' to create a test credential and check PRF");
			Log("");
			Log("Ready for testing.");
			Log("----------------------------------------");
			Log("");
		}

		private void BtnCheckApiVersion_Click(object sender, EventArgs e)
		{
			try
			{
				Log(">>> Checking Windows WebAuthn API...");
				
				if (!WebAuthnHelper.IsWebAuthnAvailable())
				{
					Log("❌ ERROR: WebAuthn API is unavailable!");
					Log("   Windows 10 22H2 or Windows 11 (WebAuthn API v4+) is required");
					return;
				}

				Log("✓ WebAuthn API is available");

				uint version = WebAuthnHelper.GetApiVersion();
				Log($"✓ API version: {version}");

				bool isPlatformAuthAvailable = false;
				int hr = WebAuthnApi.WebAuthNIsUserVerifyingPlatformAuthenticatorAvailable(out isPlatformAuthAvailable);
				
				if (hr == 0)
				{
					Log($"✓ Platform Authenticator: {(isPlatformAuthAvailable ? "Available (Windows Hello)" : "Unavailable")}");
				}
				else
				{
					Log($"⚠ Failed to check Platform Authenticator (HRESULT: 0x{hr:X8})");
				}

				Log("");
				Log("The system is ready to work with FIDO2 security keys.");
				Log("----------------------------------------");
				Log("");
			}
			catch (Exception ex)
			{
				Log($"❌ ERROR: {ex.Message}");
				Log($"   Type: {ex.GetType().Name}");
				Log("----------------------------------------");
				Log("");
			}
		}

		private void BtnTestHmacSecret_Click(object sender, EventArgs e)
		{
			try
			{
				Log(">>> Starting PRF (Pseudo-Random Function) test...");
				Log("");

				// Warn the user
				var result = MessageBox.Show(
					"A TEST credential will now be created on your FIDO2 security key.\n\n" +
					"You will need to:\n" +
					"1. Insert/connect the FIDO2 security key\n" +
					"2. Enter the key PIN\n" +
					"3. Confirm creation (touch the button on the key)\n\n" +
					"This test will NOT affect your existing databases,\n" +
					"but the test credential will remain on the key (discoverable). You can delete it\n" +
					"in Windows Settings → Accounts → Sign-in options → Security Key.\n\n" +
					"Continue the test?",
					"PRF test",
					MessageBoxButtons.YesNo,
					MessageBoxIcon.Question);

				if (result != DialogResult.Yes)
				{
					Log("Test cancelled by the user.");
					Log("----------------------------------------");
					Log("");
					return;
				}

				Log("Step 1: Creating a test credential with the PRF extension...");

				// Generate a test User ID
				byte[] testUserId = new byte[32];
				using (var rng = new System.Security.Cryptography.RNGCryptoServiceProvider())
				{
					rng.GetBytes(testUserId);
				}

				Log($"  User ID: {BitConverter.ToString(testUserId, 0, 8).Replace("-", "")}... ({testUserId.Length} bytes)");

				// Enable logging for diagnostics
				WebAuthnHelper.Logger = (msg) => Log($"  {msg}");

				// Create the credential
				byte[] credentialId;
				byte[] creationSecret;
				try
				{
					var created = WebAuthnHelper.CreateCredential(this.Handle, testUserId, "KeePass: PRF diagnostics");
					credentialId = created.CredentialId;
					creationSecret = created.PrfSecret;
					Log($"✓ Credential created successfully!");
					Log($"  Credential ID: {BitConverter.ToString(credentialId, 0, Math.Min(16, credentialId.Length)).Replace("-", "")}... ({credentialId.Length} bytes)");
					if (creationSecret != null)
						Log($"  PRF secret at creation: received ({creationSecret.Length} bytes)");
				}
				catch (WebAuthnException ex)
				{
					Log($"❌ ERROR creating credential: {ex.Message}");
					Log("----------------------------------------");
					Log("");
					WebAuthnHelper.Logger = null;
					return;
				}

				Log("");
				Log("Step 2: Getting the PRF secret from the authenticator...");
				Log("  (PIN and confirmation on the key will be required again)");

				// Pause to let the operation complete
				System.Threading.Thread.Sleep(500);

				// Get the PRF secret
				byte[] prfSecret;
				try
				{
					// allowList contains only the test credential, so real database credentials are not involved
					PrfResult assertion = WebAuthnHelper.GetPrfSecret(this.Handle, new[] { credentialId });
					prfSecret = assertion.PrfSecret;

					if (prfSecret != null && prfSecret.Length > 0)
					{
						Log($"✓✓✓ SUCCESS! PRF secret received!");
						Log($"  Length: {prfSecret.Length} bytes");
						if (creationSecret != null)
						{
							bool same = creationSecret.Length == prfSecret.Length
								&& System.Linq.Enumerable.SequenceEqual(creationSecret, prfSecret);
							Log(same
								? "  ✓ Secret matches the one received at creation (PRF is deterministic)"
								: "  ❌ Secret does NOT match the one received at creation, the key will be unreliable!");
							Array.Clear(creationSecret, 0, creationSecret.Length);
						}
						Log("");
						Log("╔════════════════════════════════════════════════════════════╗");
						Log("║  ✓ YOUR KEY SUPPORTS PRF!                                 ║");
						Log("║  ✓ It can be used for the KeePass master key             ║");
						Log("╚════════════════════════════════════════════════════════════╝");
						
						// Clear the secret from memory
						Array.Clear(prfSecret, 0, prfSecret.Length);
					}
					else
					{
						Log($"❌ PRF secret received but empty!");
						Log("  Your key may not support PRF.");
					}
				}
				catch (WebAuthnException ex)
				{
					Log($"❌ ERROR getting PRF secret: {ex.Message}");
					Log("");
					Log("╔════════════════════════════════════════════════════════════╗");
					Log("║  ❌ YOUR KEY DOES NOT SUPPORT PRF                         ║");
					Log("║     or Windows WebAuthn API did not pass the extension    ║");
					Log("╚════════════════════════════════════════════════════════════╝");
					Log("");
					Log("Possible causes:");
					Log("  1. The key does not support the PRF extension (WebAuthn Level 3)");
					Log("  2. The credential was not created with PRF (bug in the code)");
					Log("  3. Problems with the Windows WebAuthn API");
					Log("");
					Log("Recommendations:");
					Log("  - Use a modern FIDO2 security key (YubiKey 5, Google Titan, etc.)");
					Log("  - Update your key's firmware");
					Log("  - Check for Windows 11 updates");
					Log("  - Make sure you are running Windows 11 or Windows 10 22H2+");
				}

				// Disable logging
				WebAuthnHelper.Logger = null;

				Log("");
				Log("Test finished.");
				Log("----------------------------------------");
				Log("");
			}
			catch (Exception ex)
			{
				Log($"❌ UNEXPECTED ERROR: {ex.Message}");
				Log($"   Type: {ex.GetType().Name}");
				Log($"   Stack Trace: {ex.StackTrace}");
				Log("----------------------------------------");
				Log("");
				WebAuthnHelper.Logger = null;
			}
		}

		private void BtnClose_Click(object sender, EventArgs e)
		{
			this.Close();
		}

		private void Log(string message)
		{
			logBuilder.AppendLine(message);
			txtLog.Text = logBuilder.ToString();
			txtLog.SelectionStart = txtLog.Text.Length;
			txtLog.ScrollToCaret();
			Application.DoEvents(); // Refresh the UI
		}
	}
}

