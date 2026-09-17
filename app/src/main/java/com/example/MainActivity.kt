package com.example

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material.icons.outlined.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import com.example.ui.theme.MyApplicationTheme
import org.json.JSONArray
import org.json.JSONObject
import java.security.MessageDigest
import java.security.SecureRandom
import java.text.NumberFormat
import java.text.SimpleDateFormat
import java.util.*
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec

// ==========================================
// 1. DATA MODELS & SECURITY UTILITIES
// ==========================================

data class UserAccount(
  val username: String,
  val fullName: String,
  val role: String,
  val saltHex: String,
  val hashHex: String,
  val createdAt: Long = System.currentTimeMillis()
)

data class SaleRecord(
  val id: String,
  val date: String,
  val customerName: String,
  val customerPhone: String,
  val itemName: String,
  val size: String,
  val quantity: Int,
  val unitPrice: Int,
  val total: Int,
  val timestamp: Long = System.currentTimeMillis()
)

object SecurityUtils {
  private const val ITERATIONS = 10000
  private const val KEY_LENGTH = 256

  fun generateSalt(): String {
    val random = SecureRandom()
    val salt = ByteArray(16)
    random.nextBytes(salt)
    return toHex(salt)
  }

  fun hashPassword(password: String, saltHex: String): String {
    val salt = fromHex(saltHex)
    val spec = PBEKeySpec(password.toCharArray(), salt, ITERATIONS, KEY_LENGTH)
    val factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
    val hash = factory.generateSecret(spec).encoded
    return toHex(hash)
  }

  fun verifyPassword(password: String, saltHex: String, expectedHashHex: String): Boolean {
    val calculatedHash = hashPassword(password, saltHex)
    // Constant-time check against timing attacks
    return MessageDigest.isEqual(
      calculatedHash.toByteArray(Charsets.UTF_8),
      expectedHashHex.toByteArray(Charsets.UTF_8)
    )
  }

  private fun toHex(bytes: ByteArray): String = bytes.joinToString("") { "%02x".format(it) }

  private fun fromHex(hex: String): ByteArray {
    val len = hex.length
    val data = ByteArray(len / 2)
    var i = 0
    while (i < len) {
      data[i / 2] = ((Character.digit(hex[i], 16) shl 4) + Character.digit(hex[i + 1], 16)).toByte()
      i += 2
    }
    return data
  }
}

// Default seeded users for instant testing
private fun createDefaultUsers(): List<UserAccount> {
  val saltMahfuz = SecurityUtils.generateSalt()
  val hashMahfuz = SecurityUtils.hashPassword("password123", saltMahfuz)

  val saltPriya = SecurityUtils.generateSalt()
  val hashPriya = SecurityUtils.hashPassword("staff123", saltPriya)

  return listOf(
    UserAccount(
      username = "mahfuz",
      fullName = "Mahfuzur Rahman",
      role = "Store Manager",
      saltHex = saltMahfuz,
      hashHex = hashMahfuz
    ),
    UserAccount(
      username = "priya",
      fullName = "Priya Patel",
      role = "Sales Associate",
      saltHex = saltPriya,
      hashHex = hashPriya
    )
  )
}

private fun loadUsers(context: Context): List<UserAccount> {
  val prefs = context.getSharedPreferences("mav_auth_prefs", Context.MODE_PRIVATE)
  val jsonStr = prefs.getString("users_json", null) ?: return createDefaultUsers().also {
    saveUsers(context, it)
  }
  return try {
    val array = JSONArray(jsonStr)
    val list = mutableListOf<UserAccount>()
    for (i in 0 until array.length()) {
      val obj = array.getJSONObject(i)
      list.add(
        UserAccount(
          username = obj.getString("username"),
          fullName = obj.getString("fullName"),
          role = obj.getString("role"),
          saltHex = obj.getString("saltHex"),
          hashHex = obj.getString("hashHex"),
          createdAt = obj.optLong("createdAt", System.currentTimeMillis())
        )
      )
    }
    if (list.isEmpty()) createDefaultUsers().also { saveUsers(context, it) } else list
  } catch (e: Exception) {
    createDefaultUsers()
  }
}

private fun saveUsers(context: Context, users: List<UserAccount>) {
  val prefs = context.getSharedPreferences("mav_auth_prefs", Context.MODE_PRIVATE)
  val array = JSONArray()
  users.forEach { u ->
    val obj = JSONObject().apply {
      put("username", u.username)
      put("fullName", u.fullName)
      put("role", u.role)
      put("saltHex", u.saltHex)
      put("hashHex", u.hashHex)
      put("createdAt", u.createdAt)
    }
    array.put(obj)
  }
  prefs.edit().putString("users_json", array.toString()).apply()
}

private fun getActiveSession(context: Context): String? {
  val prefs = context.getSharedPreferences("mav_auth_prefs", Context.MODE_PRIVATE)
  return prefs.getString("active_session_user", null)
}

private fun saveActiveSession(context: Context, username: String?) {
  val prefs = context.getSharedPreferences("mav_auth_prefs", Context.MODE_PRIVATE)
  prefs.edit().putString("active_session_user", username).apply()
}

// ==========================================
// 2. MAIN ACTIVITY
// ==========================================

class MainActivity : ComponentActivity() {
  override fun onCreate(savedInstanceState: Bundle?) {
    super.onCreate(savedInstanceState)
    enableEdgeToEdge()

    setContent {
      var isDarkTheme by remember { mutableStateOf(true) }
      val context = LocalContext.current

      var users by remember { mutableStateOf(loadUsers(context)) }
      val initialActiveUser = remember {
        val activeUsername = getActiveSession(context)
        users.find { it.username == activeUsername }
      }
      var currentUser by remember { mutableStateOf<UserAccount?>(initialActiveUser) }

      MyApplicationTheme(darkTheme = isDarkTheme) {
        Surface(
          modifier = Modifier.fillMaxSize(),
          color = MaterialTheme.colorScheme.background
        ) {
          if (currentUser == null) {
            AuthScreen(
              users = users,
              isDarkTheme = isDarkTheme,
              onToggleTheme = { isDarkTheme = !isDarkTheme },
              onLoginSuccess = { user ->
                currentUser = user
                saveActiveSession(context, user.username)
                Toast.makeText(context, "Welcome back, ${user.fullName}!", Toast.LENGTH_SHORT).show()
              },
              onRegisterSuccess = { newUser ->
                val updated = users + newUser
                users = updated
                saveUsers(context, updated)
                currentUser = newUser
                saveActiveSession(context, newUser.username)
                Toast.makeText(context, "Account created! Welcome, ${newUser.fullName}!", Toast.LENGTH_SHORT).show()
              }
            )
          } else {
            MavClothingApp(
              currentUser = currentUser!!,
              isDarkTheme = isDarkTheme,
              onToggleTheme = { isDarkTheme = !isDarkTheme },
              onLogout = {
                currentUser = null
                saveActiveSession(context, null)
                Toast.makeText(context, "Logged out successfully", Toast.LENGTH_SHORT).show()
              }
            )
          }
        }
      }
    }
  }
}

// ==========================================
// 3. AUTHENTICATION UI COMPOSABLE
// ==========================================

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun AuthScreen(
  users: List<UserAccount>,
  isDarkTheme: Boolean,
  onToggleTheme: () -> Unit,
  onLoginSuccess: (UserAccount) -> Unit,
  onRegisterSuccess: (UserAccount) -> Unit
) {
  var selectedTab by remember { mutableIntStateOf(0) } // 0: Login, 1: Register

  // Login Form States
  var loginUsername by remember { mutableStateOf("") }
  var loginPassword by remember { mutableStateOf("") }
  var loginPasswordVisible by remember { mutableStateOf(false) }
  var loginError by remember { mutableStateOf<String?>(null) }

  // Register Form States
  var regFullName by remember { mutableStateOf("") }
  var regUsername by remember { mutableStateOf("") }
  var regRole by remember { mutableStateOf("Sales Associate") }
  var regPassword by remember { mutableStateOf("") }
  var regConfirmPassword by remember { mutableStateOf("") }
  var regPasswordVisible by remember { mutableStateOf(false) }
  var regError by remember { mutableStateOf<String?>(null) }

  val roleOptions = listOf("Store Manager", "Sales Associate", "Cashier")

  Scaffold(
    topBar = {
      TopAppBar(
        title = {
          Row(verticalAlignment = Alignment.CenterVertically) {
            Box(
              modifier = Modifier
                .size(36.dp)
                .clip(RoundedCornerShape(8.dp))
                .background(MaterialTheme.colorScheme.primary),
              contentAlignment = Alignment.Center
            ) {
              Icon(
                imageVector = Icons.Default.Checkroom,
                contentDescription = null,
                tint = MaterialTheme.colorScheme.onPrimary,
                modifier = Modifier.size(20.dp)
              )
            }
            Spacer(modifier = Modifier.width(10.dp))
            Column {
              Text(
                text = "MAV Garments",
                style = MaterialTheme.typography.titleMedium.copy(fontWeight = FontWeight.Bold)
              )
              Text(
                text = "Staff Security & Access Portal",
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.primary
              )
            }
          }
        },
        actions = {
          IconButton(onClick = onToggleTheme, modifier = Modifier.testTag("auth_theme_toggle")) {
            Icon(
              imageVector = if (isDarkTheme) Icons.Default.LightMode else Icons.Default.DarkMode,
              contentDescription = "Toggle Theme"
            )
          }
        },
        colors = TopAppBarDefaults.topAppBarColors(
          containerColor = MaterialTheme.colorScheme.surfaceColorAtElevation(3.dp)
        )
      )
    }
  ) { innerPadding ->
    LazyColumn(
      modifier = Modifier
        .fillMaxSize()
        .padding(innerPadding)
        .padding(horizontal = 20.dp),
      horizontalAlignment = Alignment.CenterHorizontally,
      verticalArrangement = Arrangement.Center,
      contentPadding = PaddingValues(vertical = 24.dp)
    ) {
      item {
        // App Identity Header
        Column(
          horizontalAlignment = Alignment.CenterHorizontally,
          modifier = Modifier.padding(bottom = 20.dp)
        ) {
          Box(
            modifier = Modifier
              .size(64.dp)
              .clip(CircleShape)
              .background(MaterialTheme.colorScheme.primaryContainer),
            contentAlignment = Alignment.Center
          ) {
            Icon(
              imageVector = Icons.Default.LockPerson,
              contentDescription = "Security Access",
              tint = MaterialTheme.colorScheme.onPrimaryContainer,
              modifier = Modifier.size(36.dp)
            )
          }
          Spacer(modifier = Modifier.height(12.dp))
          Text(
            text = "MAV Official Portal",
            style = MaterialTheme.typography.headlineSmall.copy(fontWeight = FontWeight.Black)
          )
          Text(
            text = "Enter authorized credentials to access sales & billing dashboard",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            textAlign = TextAlign.Center,
            modifier = Modifier.padding(horizontal = 16.dp, vertical = 4.dp)
          )
        }

        // Main Auth Card
        ElevatedCard(
          modifier = Modifier
            .fillMaxWidth()
            .widthIn(max = 480.dp)
            .testTag("auth_card"),
          shape = RoundedCornerShape(20.dp)
        ) {
          Column(modifier = Modifier.padding(20.dp)) {
            // Tabs: Sign In / Register
            TabRow(
              selectedTabIndex = selectedTab,
              containerColor = Color.Transparent,
              modifier = Modifier
                .fillMaxWidth()
                .padding(bottom = 20.dp)
            ) {
              Tab(
                selected = selectedTab == 0,
                onClick = {
                  selectedTab = 0
                  loginError = null
                },
                text = { Text("Sign In", fontWeight = FontWeight.Bold) }
              )
              Tab(
                selected = selectedTab == 1,
                onClick = {
                  selectedTab = 1
                  regError = null
                },
                text = { Text("Register", fontWeight = FontWeight.Bold) }
              )
            }

            if (selectedTab == 0) {
              // ---------------- LOGIN FORM ----------------
              loginError?.let { err ->
                Surface(
                  color = MaterialTheme.colorScheme.errorContainer,
                  shape = RoundedCornerShape(8.dp),
                  modifier = Modifier
                    .fillMaxWidth()
                    .padding(bottom = 12.dp)
                ) {
                  Row(
                    modifier = Modifier.padding(10.dp),
                    verticalAlignment = Alignment.CenterVertically
                  ) {
                    Icon(
                      imageVector = Icons.Default.ErrorOutline,
                      contentDescription = null,
                      tint = MaterialTheme.colorScheme.error,
                      modifier = Modifier.size(18.dp)
                    )
                    Spacer(modifier = Modifier.width(8.dp))
                    Text(
                      text = err,
                      style = MaterialTheme.typography.bodySmall,
                      color = MaterialTheme.colorScheme.onErrorContainer
                    )
                  }
                }
              }

              OutlinedTextField(
                value = loginUsername,
                onValueChange = {
                  loginUsername = it
                  loginError = null
                },
                label = { Text("Username or Staff ID") },
                placeholder = { Text("e.g. mahfuz") },
                leadingIcon = { Icon(Icons.Outlined.Person, contentDescription = null) },
                singleLine = true,
                modifier = Modifier
                  .fillMaxWidth()
                  .testTag("login_username_input"),
                keyboardOptions = KeyboardOptions(imeAction = ImeAction.Next)
              )

              Spacer(modifier = Modifier.height(12.dp))

              OutlinedTextField(
                value = loginPassword,
                onValueChange = {
                  loginPassword = it
                  loginError = null
                },
                label = { Text("Password") },
                placeholder = { Text("••••••••") },
                leadingIcon = { Icon(Icons.Outlined.Lock, contentDescription = null) },
                trailingIcon = {
                  IconButton(onClick = { loginPasswordVisible = !loginPasswordVisible }) {
                    Icon(
                      imageVector = if (loginPasswordVisible) Icons.Default.VisibilityOff else Icons.Default.Visibility,
                      contentDescription = if (loginPasswordVisible) "Hide password" else "Show password"
                    )
                  }
                },
                visualTransformation = if (loginPasswordVisible) VisualTransformation.None else PasswordVisualTransformation(),
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password, imeAction = ImeAction.Done),
                singleLine = true,
                modifier = Modifier
                  .fillMaxWidth()
                  .testTag("login_password_input")
              )

              Spacer(modifier = Modifier.height(20.dp))

              Button(
                onClick = {
                  val trimmedUser = loginUsername.trim().lowercase(Locale.ROOT)
                  if (trimmedUser.isBlank() || loginPassword.isBlank()) {
                    loginError = "Please enter both username and password."
                    return@Button
                  }

                  val account = users.find { it.username.lowercase(Locale.ROOT) == trimmedUser }
                  if (account == null) {
                    loginError = "Invalid username or password. Please try again."
                    return@Button
                  }

                  val valid = SecurityUtils.verifyPassword(loginPassword, account.saltHex, account.hashHex)
                  if (valid) {
                    loginError = null
                    onLoginSuccess(account)
                  } else {
                    loginError = "Invalid username or password. Please try again."
                  }
                },
                modifier = Modifier
                  .fillMaxWidth()
                  .height(50.dp)
                  .testTag("login_submit_button"),
                shape = RoundedCornerShape(12.dp)
              ) {
                Icon(Icons.Default.Login, contentDescription = null)
                Spacer(modifier = Modifier.width(8.dp))
                Text("Sign In to Portal", fontWeight = FontWeight.Bold)
              }

              Spacer(modifier = Modifier.height(20.dp))
              HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
              Spacer(modifier = Modifier.height(14.dp))

              // Demo Accounts Quick Access
              Text(
                text = "QUICK DEMO CREDENTIALS",
                style = MaterialTheme.typography.labelSmall.copy(fontWeight = FontWeight.Bold),
                color = MaterialTheme.colorScheme.outline
              )
              Spacer(modifier = Modifier.height(8.dp))
              Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(8.dp)
              ) {
                OutlinedButton(
                  onClick = {
                    loginUsername = "mahfuz"
                    loginPassword = "password123"
                    loginError = null
                  },
                  modifier = Modifier.weight(1f),
                  shape = RoundedCornerShape(10.dp)
                ) {
                  Text("Manager: mahfuz", fontSize = 11.sp)
                }
                OutlinedButton(
                  onClick = {
                    loginUsername = "priya"
                    loginPassword = "staff123"
                    loginError = null
                  },
                  modifier = Modifier.weight(1f),
                  shape = RoundedCornerShape(10.dp)
                ) {
                  Text("Staff: priya", fontSize = 11.sp)
                }
              }
            } else {
              // ---------------- REGISTER FORM ----------------
              regError?.let { err ->
                Surface(
                  color = MaterialTheme.colorScheme.errorContainer,
                  shape = RoundedCornerShape(8.dp),
                  modifier = Modifier
                    .fillMaxWidth()
                    .padding(bottom = 12.dp)
                ) {
                  Row(
                    modifier = Modifier.padding(10.dp),
                    verticalAlignment = Alignment.CenterVertically
                  ) {
                    Icon(
                      imageVector = Icons.Default.ErrorOutline,
                      contentDescription = null,
                      tint = MaterialTheme.colorScheme.error,
                      modifier = Modifier.size(18.dp)
                    )
                    Spacer(modifier = Modifier.width(8.dp))
                    Text(
                      text = err,
                      style = MaterialTheme.typography.bodySmall,
                      color = MaterialTheme.colorScheme.onErrorContainer
                    )
                  }
                }
              }

              OutlinedTextField(
                value = regFullName,
                onValueChange = {
                  regFullName = it
                  regError = null
                },
                label = { Text("Full Name") },
                placeholder = { Text("e.g. Mahfuzur Rahman") },
                leadingIcon = { Icon(Icons.Outlined.Badge, contentDescription = null) },
                singleLine = true,
                modifier = Modifier
                  .fillMaxWidth()
                  .testTag("reg_name_input")
              )

              Spacer(modifier = Modifier.height(10.dp))

              OutlinedTextField(
                value = regUsername,
                onValueChange = {
                  regUsername = it
                  regError = null
                },
                label = { Text("Username") },
                placeholder = { Text("e.g. mahfuz2026") },
                leadingIcon = { Icon(Icons.Outlined.AccountCircle, contentDescription = null) },
                singleLine = true,
                modifier = Modifier
                  .fillMaxWidth()
                  .testTag("reg_username_input")
              )

              Spacer(modifier = Modifier.height(10.dp))

              // Staff Role Chips
              Text(
                text = "ASSIGNED ROLE",
                style = MaterialTheme.typography.labelSmall.copy(fontWeight = FontWeight.Bold),
                color = MaterialTheme.colorScheme.outline
              )
              Spacer(modifier = Modifier.height(4.dp))
              LazyRow(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                items(roleOptions) { r ->
                  FilterChip(
                    selected = regRole == r,
                    onClick = { regRole = r },
                    label = { Text(r, fontSize = 12.sp) }
                  )
                }
              }

              Spacer(modifier = Modifier.height(10.dp))

              OutlinedTextField(
                value = regPassword,
                onValueChange = {
                  regPassword = it
                  regError = null
                },
                label = { Text("Password (min 6 characters)") },
                placeholder = { Text("••••••••") },
                leadingIcon = { Icon(Icons.Outlined.Lock, contentDescription = null) },
                trailingIcon = {
                  IconButton(onClick = { regPasswordVisible = !regPasswordVisible }) {
                    Icon(
                      imageVector = if (regPasswordVisible) Icons.Default.VisibilityOff else Icons.Default.Visibility,
                      contentDescription = null
                    )
                  }
                },
                visualTransformation = if (regPasswordVisible) VisualTransformation.None else PasswordVisualTransformation(),
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
                singleLine = true,
                modifier = Modifier
                  .fillMaxWidth()
                  .testTag("reg_password_input")
              )

              Spacer(modifier = Modifier.height(10.dp))

              OutlinedTextField(
                value = regConfirmPassword,
                onValueChange = {
                  regConfirmPassword = it
                  regError = null
                },
                label = { Text("Confirm Password") },
                placeholder = { Text("••••••••") },
                leadingIcon = { Icon(Icons.Outlined.LockClock, contentDescription = null) },
                visualTransformation = if (regPasswordVisible) VisualTransformation.None else PasswordVisualTransformation(),
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
                singleLine = true,
                modifier = Modifier
                  .fillMaxWidth()
                  .testTag("reg_confirm_password_input")
              )

              Spacer(modifier = Modifier.height(20.dp))

              Button(
                onClick = {
                  val trimmedName = regFullName.trim()
                  val trimmedUser = regUsername.trim().lowercase(Locale.ROOT)

                  if (trimmedName.length < 2) {
                    regError = "Please enter your full name."
                    return@Button
                  }
                  if (trimmedUser.length < 3) {
                    regError = "Username must be at least 3 characters."
                    return@Button
                  }
                  if (users.any { it.username.lowercase(Locale.ROOT) == trimmedUser }) {
                    regError = "Username '$trimmedUser' is already registered. Choose another."
                    return@Button
                  }
                  if (regPassword.length < 6) {
                    regError = "Password must be at least 6 characters long."
                    return@Button
                  }
                  if (regPassword != regConfirmPassword) {
                    regError = "Passwords do not match. Please re-check."
                    return@Button
                  }

                  // Generate cryptographically secure salt and PBKDF2 hash
                  val salt = SecurityUtils.generateSalt()
                  val hash = SecurityUtils.hashPassword(regPassword, salt)

                  val newAccount = UserAccount(
                    username = trimmedUser,
                    fullName = trimmedName,
                    role = regRole,
                    saltHex = salt,
                    hashHex = hash
                  )

                  regError = null
                  onRegisterSuccess(newAccount)
                },
                modifier = Modifier
                  .fillMaxWidth()
                  .height(50.dp)
                  .testTag("register_submit_button"),
                shape = RoundedCornerShape(12.dp)
              ) {
                Icon(Icons.Default.PersonAdd, contentDescription = null)
                Spacer(modifier = Modifier.width(8.dp))
                Text("Create Account & Enter Portal", fontWeight = FontWeight.Bold)
              }
            }
          }
        }

        Spacer(modifier = Modifier.height(16.dp))

        // Security Footnote
        Row(
          verticalAlignment = Alignment.CenterVertically,
          horizontalArrangement = Arrangement.Center
        ) {
          Icon(
            imageVector = Icons.Default.Shield,
            contentDescription = null,
            modifier = Modifier.size(16.dp),
            tint = Color(0xFF10B981)
          )
          Spacer(modifier = Modifier.width(6.dp))
          Text(
            text = "PBKDF2-HMAC-SHA256 Cryptographic Credential Protection",
            style = MaterialTheme.typography.labelSmall,
            color = MaterialTheme.colorScheme.outline
          )
        }
      }
    }
  }
}

// ==========================================
// 4. MAIN CLOTHING DASHBOARD (AUTHENTICATED)
// ==========================================

private fun formatINR(amount: Number): String {
  val formatter = NumberFormat.getCurrencyInstance(Locale("en", "IN"))
  formatter.maximumFractionDigits = 0
  return formatter.format(amount)
}

private val DEFAULT_SALES = listOf(
  SaleRecord(
    id = "MAV-2026-0045",
    date = SimpleDateFormat("yyyy-MM-dd", Locale.getDefault()).format(Date()),
    customerName = "Rahul Sharma",
    customerPhone = "+91 98765 43210",
    itemName = "Slim Fit Denim Jeans",
    size = "32",
    quantity = 1,
    unitPrice = 1499,
    total = 1499
  ),
  SaleRecord(
    id = "MAV-2026-0044",
    date = SimpleDateFormat("yyyy-MM-dd", Locale.getDefault()).format(Date()),
    customerName = "Priya Patel",
    customerPhone = "+91 91234 56789",
    itemName = "Embroidered Cotton Kurti",
    size = "M",
    quantity = 2,
    unitPrice = 899,
    total = 1798
  ),
  SaleRecord(
    id = "MAV-2026-0043",
    date = SimpleDateFormat("yyyy-MM-dd", Locale.getDefault()).format(Date(System.currentTimeMillis() - 86400000L)),
    customerName = "Amit Verma",
    customerPhone = "+91 99887 76655",
    itemName = "Casual Cotton Formal Shirt",
    size = "XL",
    quantity = 2,
    unitPrice = 1199,
    total = 2398
  ),
  SaleRecord(
    id = "MAV-2026-0042",
    date = SimpleDateFormat("yyyy-MM-dd", Locale.getDefault()).format(Date(System.currentTimeMillis() - 86400000L * 2)),
    customerName = "Sneha Roy",
    customerPhone = "+91 98321 09876",
    itemName = "Round Neck Graphic T-Shirt",
    size = "S",
    quantity = 3,
    unitPrice = 499,
    total = 1497
  )
)

private fun loadSales(context: Context): List<SaleRecord> {
  val prefs = context.getSharedPreferences("mav_sales_prefs", Context.MODE_PRIVATE)
  val jsonString = prefs.getString("sales_json", null) ?: return DEFAULT_SALES
  return try {
    val array = JSONArray(jsonString)
    val list = mutableListOf<SaleRecord>()
    for (i in 0 until array.length()) {
      val obj = array.getJSONObject(i)
      list.add(
        SaleRecord(
          id = obj.getString("id"),
          date = obj.getString("date"),
          customerName = obj.getString("customerName"),
          customerPhone = obj.getString("customerPhone"),
          itemName = obj.getString("itemName"),
          size = obj.optString("size", "M"),
          quantity = obj.getInt("quantity"),
          unitPrice = obj.getInt("unitPrice"),
          total = obj.getInt("total"),
          timestamp = obj.optLong("timestamp", System.currentTimeMillis())
        )
      )
    }
    list
  } catch (e: Exception) {
    DEFAULT_SALES
  }
}

private fun saveSales(context: Context, sales: List<SaleRecord>) {
  val prefs = context.getSharedPreferences("mav_sales_prefs", Context.MODE_PRIVATE)
  val array = JSONArray()
  sales.forEach { s ->
    val obj = JSONObject().apply {
      put("id", s.id)
      put("date", s.date)
      put("customerName", s.customerName)
      put("customerPhone", s.customerPhone)
      put("itemName", s.itemName)
      put("size", s.size)
      put("quantity", s.quantity)
      put("unitPrice", s.unitPrice)
      put("total", s.total)
      put("timestamp", s.timestamp)
    }
    array.put(obj)
  }
  prefs.edit().putString("sales_json", array.toString()).apply()
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun MavClothingApp(
  currentUser: UserAccount,
  isDarkTheme: Boolean,
  onToggleTheme: () -> Unit,
  onLogout: () -> Unit
) {
  val context = LocalContext.current
  var sales by remember { mutableStateOf(loadSales(context)) }
  var selectedInvoice by remember { mutableStateOf<SaleRecord?>(null) }
  var showResetDialog by remember { mutableStateOf(false) }
  var showLogoutConfirm by remember { mutableStateOf(false) }

  // Form State
  val todayStr = remember { SimpleDateFormat("yyyy-MM-dd", Locale.getDefault()).format(Date()) }
  var billDate by remember { mutableStateOf(todayStr) }
  var customerName by remember { mutableStateOf("") }
  var customerPhone by remember { mutableStateOf("") }
  var itemName by remember { mutableStateOf("") }
  var selectedSize by remember { mutableStateOf("M") }
  var quantityText by remember { mutableStateOf("1") }
  var unitPriceText by remember { mutableStateOf("") }
  var searchQuery by remember { mutableStateOf("") }

  val quantity = quantityText.toIntOrNull() ?: 0
  val unitPrice = unitPriceText.toIntOrNull() ?: 0
  val currentTotal = quantity * unitPrice

  // Quick Items
  val quickItems = listOf(
    "Jeans" to 1499,
    "Kurti" to 899,
    "Shirt" to 1199,
    "T-Shirt" to 499,
    "Chinos" to 1299
  )
  val sizes = listOf("S", "M", "L", "XL", "XXL", "32", "34", "36")

  // Dashboard Metrics
  val todaySales = sales.filter { it.date == todayStr }.sumOf { it.total }
  val todayBillsCount = sales.count { it.date == todayStr }
  val totalBillsCount = sales.size
  val calendar = Calendar.getInstance()
  val currentYear = calendar.get(Calendar.YEAR)
  val currentMonth = calendar.get(Calendar.MONTH)
  val monthlyRevenue = sales.filter {
    try {
      val parsedDate = SimpleDateFormat("yyyy-MM-dd", Locale.getDefault()).parse(it.date)
      if (parsedDate != null) {
        val cal = Calendar.getInstance().apply { time = parsedDate }
        cal.get(Calendar.YEAR) == currentYear && cal.get(Calendar.MONTH) == currentMonth
      } else false
    } catch (e: Exception) {
      false
    }
  }.sumOf { it.total }

  // Filtered List
  val filteredSales = sales.filter { s ->
    if (searchQuery.isBlank()) true
    else {
      s.customerName.contains(searchQuery, ignoreCase = true) ||
      s.customerPhone.contains(searchQuery, ignoreCase = true) ||
      s.itemName.contains(searchQuery, ignoreCase = true) ||
      s.id.contains(searchQuery, ignoreCase = true)
    }
  }

  Scaffold(
    topBar = {
      TopAppBar(
        title = {
          Row(verticalAlignment = Alignment.CenterVertically) {
            Box(
              modifier = Modifier
                .size(38.dp)
                .clip(RoundedCornerShape(10.dp))
                .background(MaterialTheme.colorScheme.primary),
              contentAlignment = Alignment.Center
            ) {
              Icon(
                imageVector = Icons.Default.Checkroom,
                contentDescription = "Store Logo",
                tint = MaterialTheme.colorScheme.onPrimary,
                modifier = Modifier.size(20.dp)
              )
            }
            Spacer(modifier = Modifier.width(10.dp))
            Column {
              Text(
                text = "MAV Garments",
                style = MaterialTheme.typography.titleMedium.copy(fontWeight = FontWeight.Bold)
              )
              Row(verticalAlignment = Alignment.CenterVertically) {
                Text(
                  text = currentUser.fullName,
                  style = MaterialTheme.typography.labelSmall.copy(fontWeight = FontWeight.SemiBold),
                  color = MaterialTheme.colorScheme.primary
                )
                Text(
                  text = " • ${currentUser.role}",
                  style = MaterialTheme.typography.labelSmall,
                  color = MaterialTheme.colorScheme.outline
                )
              }
            }
          }
        },
        actions = {
          IconButton(onClick = onToggleTheme, modifier = Modifier.testTag("theme_toggle_button")) {
            Icon(
              imageVector = if (isDarkTheme) Icons.Default.LightMode else Icons.Default.DarkMode,
              contentDescription = "Toggle Theme"
            )
          }
          IconButton(onClick = { showResetDialog = true }, modifier = Modifier.testTag("reset_button")) {
            Icon(
              imageVector = Icons.Default.Refresh,
              contentDescription = "Reset Demo Data"
            )
          }
          IconButton(
            onClick = { showLogoutConfirm = true },
            modifier = Modifier.testTag("logout_button")
          ) {
            Icon(
              imageVector = Icons.Default.Logout,
              contentDescription = "Sign Out",
              tint = MaterialTheme.colorScheme.error
            )
          }
        },
        colors = TopAppBarDefaults.topAppBarColors(
          containerColor = MaterialTheme.colorScheme.surfaceColorAtElevation(3.dp)
        )
      )
    }
  ) { innerPadding ->
    LazyColumn(
      modifier = Modifier
        .fillMaxSize()
        .padding(innerPadding)
        .padding(horizontal = 16.dp),
      verticalArrangement = Arrangement.spacedBy(16.dp),
      contentPadding = PaddingValues(vertical = 16.dp)
    ) {
      // 1. Dashboard Metrics Grid
      item {
        Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
          Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(10.dp)
          ) {
            MetricCard(
              title = "Today's Sales",
              value = formatINR(todaySales),
              subtitle = "$todayBillsCount bills today",
              modifier = Modifier.weight(1f),
              accentColor = MaterialTheme.colorScheme.primary
            )
            MetricCard(
              title = "Total Bills",
              value = totalBillsCount.toString(),
              subtitle = "All-time receipts",
              modifier = Modifier.weight(1f),
              accentColor = MaterialTheme.colorScheme.secondary
            )
          }
          Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(10.dp)
          ) {
            MetricCard(
              title = "Monthly Sales",
              value = formatINR(monthlyRevenue),
              subtitle = SimpleDateFormat("MMMM yyyy", Locale.getDefault()).format(Date()),
              modifier = Modifier.weight(1f),
              accentColor = MaterialTheme.colorScheme.tertiary
            )
            MetricCard(
              title = "Active Staff",
              value = currentUser.username,
              subtitle = currentUser.role,
              modifier = Modifier.weight(1f),
              accentColor = Color(0xFF10B981)
            )
          }
        }
      }

      // 2. New Garment Sales Form
      item {
        ElevatedCard(
          modifier = Modifier
            .fillMaxWidth()
            .testTag("sales_form_card"),
          shape = RoundedCornerShape(16.dp)
        ) {
          Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            Row(
              modifier = Modifier.fillMaxWidth(),
              horizontalArrangement = Arrangement.SpaceBetween,
              verticalAlignment = Alignment.CenterVertically
            ) {
              Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(
                  imageVector = Icons.Default.ReceiptLong,
                  contentDescription = null,
                  tint = MaterialTheme.colorScheme.primary
                )
                Spacer(modifier = Modifier.width(8.dp))
                Text(
                  text = "New Clothing Bill",
                  style = MaterialTheme.typography.titleMedium.copy(fontWeight = FontWeight.Bold)
                )
              }
              Surface(
                color = MaterialTheme.colorScheme.primaryContainer,
                shape = RoundedCornerShape(8.dp)
              ) {
                Text(
                  text = "POS Billing",
                  style = MaterialTheme.typography.labelSmall.copy(fontWeight = FontWeight.Bold),
                  color = MaterialTheme.colorScheme.onPrimaryContainer,
                  modifier = Modifier.padding(horizontal = 8.dp, vertical = 4.dp)
                )
              }
            }

            // Customer Name & Phone
            OutlinedTextField(
              value = customerName,
              onValueChange = { customerName = it },
              label = { Text("Customer Name") },
              placeholder = { Text("e.g. Rahul Sharma") },
              leadingIcon = { Icon(Icons.Outlined.Person, contentDescription = null) },
              modifier = Modifier
                .fillMaxWidth()
                .testTag("customer_name_input"),
              singleLine = true
            )

            OutlinedTextField(
              value = customerPhone,
              onValueChange = { customerPhone = it },
              label = { Text("Customer Phone (+91)") },
              placeholder = { Text("+91 98765 43210") },
              leadingIcon = { Icon(Icons.Outlined.Phone, contentDescription = null) },
              keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Phone),
              modifier = Modifier
                .fillMaxWidth()
                .testTag("customer_phone_input"),
              singleLine = true
            )

            // Clothing Item & Quick Tags
            OutlinedTextField(
              value = itemName,
              onValueChange = { itemName = it },
              label = { Text("Clothing Item") },
              placeholder = { Text("e.g. Slim Fit Denim Jeans") },
              leadingIcon = { Icon(Icons.Outlined.Checkroom, contentDescription = null) },
              modifier = Modifier
                .fillMaxWidth()
                .testTag("item_name_input"),
              singleLine = true
            )

            LazyRow(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
              items(quickItems) { (name, price) ->
                SuggestionChip(
                  onClick = {
                    itemName = name
                    unitPriceText = price.toString()
                  },
                  label = { Text("$name (₹$price)", fontSize = 12.sp) }
                )
              }
            }

            // Garment Size
            Text(
              text = "GARMENT SIZE",
              style = MaterialTheme.typography.labelSmall.copy(fontWeight = FontWeight.Bold),
              color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            LazyRow(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
              items(sizes) { s ->
                FilterChip(
                  selected = selectedSize == s,
                  onClick = { selectedSize = s },
                  label = { Text(s, fontWeight = FontWeight.Bold) }
                )
              }
            }

            // Quantity and Unit Price
            Row(
              modifier = Modifier.fillMaxWidth(),
              horizontalArrangement = Arrangement.spacedBy(12.dp)
            ) {
              OutlinedTextField(
                value = quantityText,
                onValueChange = { quantityText = it },
                label = { Text("Quantity") },
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                modifier = Modifier
                  .weight(1f)
                  .testTag("quantity_input"),
                singleLine = true
              )
              OutlinedTextField(
                value = unitPriceText,
                onValueChange = { unitPriceText = it },
                label = { Text("Price (₹)") },
                placeholder = { Text("999") },
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                modifier = Modifier
                  .weight(1f)
                  .testTag("unit_price_input"),
                singleLine = true
              )
            }

            // Live Calculation Total Banner
            Surface(
              modifier = Modifier.fillMaxWidth(),
              color = MaterialTheme.colorScheme.surfaceVariant,
              shape = RoundedCornerShape(12.dp)
            ) {
              Row(
                modifier = Modifier
                  .fillMaxWidth()
                  .padding(14.dp),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
              ) {
                Text(
                  text = "Bill Total Amount:",
                  style = MaterialTheme.typography.titleSmall.copy(fontWeight = FontWeight.SemiBold)
                )
                Text(
                  text = formatINR(currentTotal),
                  style = MaterialTheme.typography.titleLarge.copy(
                    fontWeight = FontWeight.Black,
                    fontFamily = FontFamily.Monospace,
                    color = MaterialTheme.colorScheme.primary
                  )
                )
              }
            }

            // Save Action Button
            Button(
              onClick = {
                if (customerName.isBlank() || customerPhone.isBlank() || itemName.isBlank() || quantity <= 0 || unitPrice <= 0) {
                  Toast.makeText(context, "Please fill in all sales details properly", Toast.LENGTH_SHORT).show()
                  return@Button
                }

                val newId = "MAV-2026-${String.format(Locale.US, "%04d", sales.size + 46)}"
                val newRecord = SaleRecord(
                  id = newId,
                  date = billDate,
                  customerName = customerName.trim(),
                  customerPhone = customerPhone.trim(),
                  itemName = itemName.trim(),
                  size = selectedSize,
                  quantity = quantity,
                  unitPrice = unitPrice,
                  total = currentTotal
                )

                val updated = listOf(newRecord) + sales
                sales = updated
                saveSales(context, updated)

                // Reset fields
                customerName = ""
                customerPhone = ""
                itemName = ""
                quantityText = "1"
                unitPriceText = ""
                Toast.makeText(context, "Bill $newId created! (${formatINR(currentTotal)})", Toast.LENGTH_SHORT).show()
                selectedInvoice = newRecord
              },
              modifier = Modifier
                .fillMaxWidth()
                .height(50.dp)
                .testTag("save_bill_button"),
              shape = RoundedCornerShape(12.dp)
            ) {
              Icon(Icons.Default.Check, contentDescription = null)
              Spacer(modifier = Modifier.width(8.dp))
              Text("Save & Generate Bill (₹)", fontWeight = FontWeight.Bold)
            }
          }
        }
      }

      // 3. Search and Records Header
      item {
        Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
          Text(
            text = "Clothing Sales Records",
            style = MaterialTheme.typography.titleMedium.copy(fontWeight = FontWeight.Bold)
          )
          OutlinedTextField(
            value = searchQuery,
            onValueChange = { searchQuery = it },
            placeholder = { Text("Search by customer, phone, garment...") },
            leadingIcon = { Icon(Icons.Default.Search, contentDescription = null) },
            trailingIcon = {
              if (searchQuery.isNotEmpty()) {
                IconButton(onClick = { searchQuery = "" }) {
                  Icon(Icons.Default.Close, contentDescription = "Clear search")
                }
              }
            },
            modifier = Modifier
              .fillMaxWidth()
              .testTag("search_input"),
            singleLine = true,
            shape = RoundedCornerShape(12.dp)
          )
          Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween
          ) {
            Text(
              text = "Showing ${filteredSales.size} of ${sales.size} transactions",
              style = MaterialTheme.typography.bodySmall,
              color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            val filteredSum = filteredSales.sumOf { it.total }
            Text(
              text = "Total: ${formatINR(filteredSum)}",
              style = MaterialTheme.typography.bodySmall.copy(fontWeight = FontWeight.Bold),
              color = MaterialTheme.colorScheme.primary
            )
          }
        }
      }

      // 4. Sales Records List
      if (filteredSales.isEmpty()) {
        item {
          Card(
            modifier = Modifier.fillMaxWidth(),
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant)
          ) {
            Column(
              modifier = Modifier
                .fillMaxWidth()
                .padding(32.dp),
              horizontalAlignment = Alignment.CenterHorizontally,
              verticalArrangement = Arrangement.spacedBy(8.dp)
            ) {
              Icon(
                imageVector = Icons.Default.SearchOff,
                contentDescription = null,
                modifier = Modifier.size(48.dp),
                tint = MaterialTheme.colorScheme.onSurfaceVariant
              )
              Text("No Clothing Bills Found", fontWeight = FontWeight.Bold)
              Text(
                "Try searching for another customer name, phone number, or garment item.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                textAlign = TextAlign.Center
              )
            }
          }
        }
      } else {
        items(filteredSales, key = { it.id }) { sale ->
          SaleItemCard(
            sale = sale,
            onOpenInvoice = { selectedInvoice = sale },
            onDelete = {
              val updated = sales.filter { it.id != sale.id }
              sales = updated
              saveSales(context, updated)
              Toast.makeText(context, "Deleted bill ${sale.id}", Toast.LENGTH_SHORT).show()
            }
          )
        }
      }
    }
  }

  // Invoice Dialog
  selectedInvoice?.let { invoice ->
    InvoiceDialog(
      sale = invoice,
      storeManagerName = currentUser.fullName,
      onDismiss = { selectedInvoice = null }
    )
  }

  // Logout Confirmation Dialog
  if (showLogoutConfirm) {
    AlertDialog(
      onDismissRequest = { showLogoutConfirm = false },
      title = { Text("Sign Out of Portal?") },
      text = { Text("Are you sure you want to sign out from ${currentUser.fullName} (${currentUser.role})?") },
      confirmButton = {
        TextButton(
          onClick = {
            showLogoutConfirm = false
            onLogout()
          }
        ) {
          Text("Sign Out", color = MaterialTheme.colorScheme.error, fontWeight = FontWeight.Bold)
        }
      },
      dismissButton = {
        TextButton(onClick = { showLogoutConfirm = false }) {
          Text("Cancel")
        }
      }
    )
  }

  // Reset Confirmation Dialog
  if (showResetDialog) {
    AlertDialog(
      onDismissRequest = { showResetDialog = false },
      title = { Text("Reset Demo Bills?") },
      text = { Text("This will restore default sample clothing transactions for MAV Garments.") },
      confirmButton = {
        TextButton(
          onClick = {
            sales = DEFAULT_SALES
            saveSales(context, DEFAULT_SALES)
            showResetDialog = false
            Toast.makeText(context, "Demo bills restored", Toast.LENGTH_SHORT).show()
          }
        ) {
          Text("Reset", color = MaterialTheme.colorScheme.error)
        }
      },
      dismissButton = {
        TextButton(onClick = { showResetDialog = false }) {
          Text("Cancel")
        }
      }
    )
  }
}

// ==========================================
// 5. HELPER COMPOSABLES
// ==========================================

@Composable
fun MetricCard(
  title: String,
  value: String,
  subtitle: String,
  modifier: Modifier = Modifier,
  accentColor: Color
) {
  ElevatedCard(
    modifier = modifier,
    shape = RoundedCornerShape(14.dp)
  ) {
    Column(modifier = Modifier.padding(14.dp)) {
      Text(
        text = title.uppercase(),
        style = MaterialTheme.typography.labelSmall.copy(fontWeight = FontWeight.Bold, letterSpacing = 0.5.sp),
        color = MaterialTheme.colorScheme.onSurfaceVariant
      )
      Spacer(modifier = Modifier.height(4.dp))
      Text(
        text = value,
        style = MaterialTheme.typography.headlineSmall.copy(
          fontWeight = FontWeight.Black,
          fontFamily = FontFamily.Monospace,
          color = accentColor
        )
      )
      Spacer(modifier = Modifier.height(2.dp))
      Text(
        text = subtitle,
        style = MaterialTheme.typography.labelSmall,
        color = MaterialTheme.colorScheme.outline
      )
    }
  }
}

@Composable
fun SaleItemCard(
  sale: SaleRecord,
  onOpenInvoice: () -> Unit,
  onDelete: () -> Unit
) {
  ElevatedCard(
    modifier = Modifier.fillMaxWidth(),
    shape = RoundedCornerShape(14.dp)
  ) {
    Column(modifier = Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
      Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically
      ) {
        Column {
          Text(
            text = sale.customerName,
            style = MaterialTheme.typography.titleMedium.copy(fontWeight = FontWeight.Bold)
          )
          Text(
            text = sale.customerPhone,
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant
          )
        }
        Column(horizontalAlignment = Alignment.End) {
          Text(
            text = formatINR(sale.total),
            style = MaterialTheme.typography.titleMedium.copy(
              fontWeight = FontWeight.Black,
              fontFamily = FontFamily.Monospace,
              color = MaterialTheme.colorScheme.primary
            )
          )
          Surface(
            color = Color(0xFF10B981).copy(alpha = 0.15f),
            shape = RoundedCornerShape(4.dp)
          ) {
            Text(
              text = "PAID",
              color = Color(0xFF10B981),
              style = MaterialTheme.typography.labelSmall.copy(fontWeight = FontWeight.Bold),
              modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp)
            )
          }
        }
      }

      HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.5f))

      Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically
      ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
          Text(
            text = sale.itemName,
            style = MaterialTheme.typography.bodyMedium.copy(fontWeight = FontWeight.Medium)
          )
          Spacer(modifier = Modifier.width(8.dp))
          Surface(
            color = MaterialTheme.colorScheme.secondaryContainer,
            shape = RoundedCornerShape(6.dp)
          ) {
            Text(
              text = "Size: ${sale.size}",
              style = MaterialTheme.typography.labelSmall.copy(fontWeight = FontWeight.Bold),
              modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp),
              color = MaterialTheme.colorScheme.onSecondaryContainer
            )
          }
          Spacer(modifier = Modifier.width(6.dp))
          Text(
            text = "× ${sale.quantity}",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.outline
          )
        }

        Row(horizontalArrangement = Arrangement.spacedBy(4.dp)) {
          FilledTonalButton(
            onClick = onOpenInvoice,
            contentPadding = PaddingValues(horizontal = 10.dp, vertical = 4.dp),
            shape = RoundedCornerShape(8.dp),
            modifier = Modifier.height(34.dp)
          ) {
            Icon(Icons.Default.Receipt, contentDescription = null, modifier = Modifier.size(16.dp))
            Spacer(modifier = Modifier.width(4.dp))
            Text("Bill", style = MaterialTheme.typography.labelMedium.copy(fontWeight = FontWeight.Bold))
          }
          IconButton(
            onClick = onDelete,
            modifier = Modifier.size(34.dp)
          ) {
            Icon(
              Icons.Outlined.Delete,
              contentDescription = "Delete",
              tint = MaterialTheme.colorScheme.error.copy(alpha = 0.7f),
              modifier = Modifier.size(18.dp)
            )
          }
        }
      }

      Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween
      ) {
        Text(
          text = sale.id,
          style = MaterialTheme.typography.labelSmall.copy(fontFamily = FontFamily.Monospace),
          color = MaterialTheme.colorScheme.outline
        )
        Text(
          text = sale.date,
          style = MaterialTheme.typography.labelSmall,
          color = MaterialTheme.colorScheme.outline
        )
      }
    }
  }
}

@Composable
fun InvoiceDialog(
  sale: SaleRecord,
  storeManagerName: String,
  onDismiss: () -> Unit
) {
  val context = LocalContext.current

  Dialog(
    onDismissRequest = onDismiss,
    properties = DialogProperties(usePlatformDefaultWidth = false)
  ) {
    Surface(
      modifier = Modifier
        .fillMaxWidth(0.92f)
        .wrapContentHeight(),
      shape = RoundedCornerShape(20.dp),
      color = Color.White
    ) {
      Column(
        modifier = Modifier
          .padding(20.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp)
      ) {
        // Receipt Header
        Row(
          modifier = Modifier.fillMaxWidth(),
          horizontalArrangement = Arrangement.SpaceBetween,
          verticalAlignment = Alignment.Top
        ) {
          Column {
            Text(
              text = "MAV Garments",
              style = MaterialTheme.typography.headlineSmall.copy(
                fontWeight = FontWeight.Black,
                color = Color(0xFF0F172A)
              )
            )
            Text(
              text = "Mahfuz Official Clothing Store",
              style = MaterialTheme.typography.labelSmall.copy(
                fontWeight = FontWeight.Bold,
                color = Color(0xFFD97706)
              )
            )
            Text(
              text = "Premium Men's & Women's Wear",
              style = MaterialTheme.typography.labelSmall,
              color = Color(0xFF64748B)
            )
          }
          Column(horizontalAlignment = Alignment.End) {
            Surface(
              color = Color(0xFFDCFCE7),
              shape = RoundedCornerShape(6.dp)
            ) {
              Text(
                text = "● CASH MEMO",
                color = Color(0xFF166534),
                style = MaterialTheme.typography.labelSmall.copy(fontWeight = FontWeight.Bold),
                modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp)
              )
            }
            Spacer(modifier = Modifier.height(4.dp))
            Text(
              text = sale.id,
              style = MaterialTheme.typography.labelMedium.copy(
                fontWeight = FontWeight.Black,
                fontFamily = FontFamily.Monospace,
                color = Color(0xFF0F172A)
              )
            )
            Text(
              text = sale.date,
              style = MaterialTheme.typography.labelSmall,
              color = Color(0xFF64748B)
            )
          }
        }

        HorizontalDivider(thickness = 2.dp, color = Color(0xFF0F172A))

        // Customer Details Box
        Surface(
          modifier = Modifier.fillMaxWidth(),
          color = Color(0xFFF8FAFC),
          shape = RoundedCornerShape(10.dp)
        ) {
          Row(
            modifier = Modifier
              .fillMaxWidth()
              .padding(10.dp),
            horizontalArrangement = Arrangement.SpaceBetween
          ) {
            Column {
              Text(
                text = "CUSTOMER DETAILS",
                style = MaterialTheme.typography.labelSmall.copy(
                  fontWeight = FontWeight.Bold,
                  fontSize = 9.sp,
                  color = Color(0xFF94A3B8)
                )
              )
              Text(
                text = sale.customerName,
                style = MaterialTheme.typography.bodyMedium.copy(
                  fontWeight = FontWeight.Bold,
                  color = Color(0xFF0F172A)
                )
              )
              Text(
                text = sale.customerPhone,
                style = MaterialTheme.typography.bodySmall,
                color = Color(0xFF475569)
              )
            }
            Column(horizontalAlignment = Alignment.End) {
              Text(
                text = "PAYMENT STATUS",
                style = MaterialTheme.typography.labelSmall.copy(
                  fontWeight = FontWeight.Bold,
                  fontSize = 9.sp,
                  color = Color(0xFF94A3B8)
                )
              )
              Text(
                text = "PAID (₹ Full)",
                style = MaterialTheme.typography.bodyMedium.copy(
                  fontWeight = FontWeight.Bold,
                  color = Color(0xFF16A34A)
                )
              )
              Text(
                text = "Cash / UPI / Card",
                style = MaterialTheme.typography.bodySmall,
                color = Color(0xFF475569)
              )
            }
          }
        }

        // Item Table
        Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
          Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween
          ) {
            Text("ITEM & SIZE", style = MaterialTheme.typography.labelSmall.copy(fontWeight = FontWeight.Bold, color = Color(0xFF64748B)))
            Text("QTY", style = MaterialTheme.typography.labelSmall.copy(fontWeight = FontWeight.Bold, color = Color(0xFF64748B)))
            Text("PRICE", style = MaterialTheme.typography.labelSmall.copy(fontWeight = FontWeight.Bold, color = Color(0xFF64748B)))
            Text("TOTAL (₹)", style = MaterialTheme.typography.labelSmall.copy(fontWeight = FontWeight.Bold, color = Color(0xFF64748B)))
          }
          HorizontalDivider(color = Color(0xFFE2E8F0))
          Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
          ) {
            Column(modifier = Modifier.weight(1.8f)) {
              Text(
                text = sale.itemName,
                style = MaterialTheme.typography.bodyMedium.copy(fontWeight = FontWeight.Bold, color = Color(0xFF0F172A))
              )
              Text(
                text = "Size: ${sale.size}",
                style = MaterialTheme.typography.bodySmall.copy(color = Color(0xFF64748B))
              )
            }
            Text(
              text = sale.quantity.toString(),
              modifier = Modifier.weight(0.5f),
              style = MaterialTheme.typography.bodyMedium.copy(fontWeight = FontWeight.Bold, color = Color(0xFF0F172A)),
              textAlign = TextAlign.Center
            )
            Text(
              text = formatINR(sale.unitPrice),
              modifier = Modifier.weight(1f),
              style = MaterialTheme.typography.bodyMedium.copy(fontFamily = FontFamily.Monospace, color = Color(0xFF0F172A)),
              textAlign = TextAlign.End
            )
            Text(
              text = formatINR(sale.total),
              modifier = Modifier.weight(1f),
              style = MaterialTheme.typography.bodyMedium.copy(
                fontWeight = FontWeight.Black,
                fontFamily = FontFamily.Monospace,
                color = Color(0xFF0F172A)
              ),
              textAlign = TextAlign.End
            )
          }
        }

        HorizontalDivider(thickness = 2.dp, color = Color(0xFF0F172A))

        // Grand Total
        Row(
          modifier = Modifier.fillMaxWidth(),
          horizontalArrangement = Arrangement.SpaceBetween,
          verticalAlignment = Alignment.CenterVertically
        ) {
          Column {
            Text(
              text = "Thank you for shopping at MAV!",
              style = MaterialTheme.typography.bodySmall.copy(fontWeight = FontWeight.Bold, color = Color(0xFF0F172A))
            )
            Text(
              text = "Exchange valid within 7 days with original tags.",
              style = MaterialTheme.typography.labelSmall.copy(fontSize = 9.sp, color = Color(0xFF64748B))
            )
          }
          Column(horizontalAlignment = Alignment.End) {
            Text(
              text = "GRAND TOTAL",
              style = MaterialTheme.typography.labelSmall.copy(fontWeight = FontWeight.Bold, color = Color(0xFF64748B))
            )
            Text(
              text = formatINR(sale.total),
              style = MaterialTheme.typography.headlineSmall.copy(
                fontWeight = FontWeight.Black,
                fontFamily = FontFamily.Monospace,
                color = Color(0xFFD97706)
              )
            )
          }
        }

        // Store Manager signature
        Row(
          modifier = Modifier.fillMaxWidth(),
          horizontalArrangement = Arrangement.SpaceBetween,
          verticalAlignment = Alignment.CenterVertically
        ) {
          Text(
            text = "Verified Computer Receipt",
            style = MaterialTheme.typography.labelSmall.copy(fontSize = 10.sp, color = Color(0xFF94A3B8))
          )
          Column(horizontalAlignment = Alignment.End) {
            Text(
              text = storeManagerName,
              style = MaterialTheme.typography.bodySmall.copy(fontWeight = FontWeight.Bold, color = Color(0xFF0F172A))
            )
            Text(
              text = "Issuing Officer",
              style = MaterialTheme.typography.labelSmall.copy(fontSize = 8.sp, color = Color(0xFF64748B))
            )
          }
        }

        // Action Buttons (WhatsApp, Copy, Close)
        Row(
          modifier = Modifier.fillMaxWidth(),
          horizontalArrangement = Arrangement.spacedBy(8.dp)
        ) {
          Button(
            onClick = {
              val phoneClean = sale.customerPhone.replace(Regex("[^0-9]"), "")
              val message = """
                *🧾 MAV Garments - Official Bill Receipt*
                *Store:* MAV - Clothing Store
                *Invoice No:* ${sale.id}
                *Date:* ${sale.date}
                *Customer:* ${sale.customerName}
                ----------------------------------------
                *Item:* ${sale.itemName}
                *Size:* ${sale.size}
                *Quantity:* ${sale.quantity}
                *Price/Unit:* ${formatINR(sale.unitPrice)}
                ----------------------------------------
                *GRAND TOTAL:* ${formatINR(sale.total)}
                *Payment Status:* PAID (Full) ✅
                ----------------------------------------
                *Thank You for Shopping at MAV Garments!*
                _Issued by: ${storeManagerName}_
              """.trimIndent()

              val encoded = Uri.encode(message)
              val waUrl = if (phoneClean.isNotBlank()) {
                "https://api.whatsapp.com/send?phone=$phoneClean&text=$encoded"
              } else {
                "https://api.whatsapp.com/send?text=$encoded"
              }
              try {
                val intent = Intent(Intent.ACTION_VIEW, Uri.parse(waUrl))
                context.startActivity(intent)
              } catch (e: Exception) {
                Toast.makeText(context, "Could not open WhatsApp", Toast.LENGTH_SHORT).show()
              }
            },
            colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF16A34A)),
            modifier = Modifier.weight(1f),
            shape = RoundedCornerShape(10.dp)
          ) {
            Icon(Icons.Default.Share, contentDescription = null, modifier = Modifier.size(16.dp))
            Spacer(modifier = Modifier.width(4.dp))
            Text("WhatsApp", fontSize = 12.sp, fontWeight = FontWeight.Bold)
          }

          OutlinedButton(
            onClick = {
              val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
              val clip = ClipData.newPlainText("Bill", "MAV Garments Bill ${sale.id}: ${sale.customerName}, ${sale.itemName} (${sale.size}), Total: ${formatINR(sale.total)}")
              clipboard.setPrimaryClip(clip)
              Toast.makeText(context, "Bill text copied to clipboard!", Toast.LENGTH_SHORT).show()
            },
            modifier = Modifier.weight(1f),
            shape = RoundedCornerShape(10.dp)
          ) {
            Icon(Icons.Default.ContentCopy, contentDescription = null, modifier = Modifier.size(16.dp))
            Spacer(modifier = Modifier.width(4.dp))
            Text("Copy", fontSize = 12.sp, fontWeight = FontWeight.Bold)
          }

          TextButton(
            onClick = onDismiss,
            shape = RoundedCornerShape(10.dp)
          ) {
            Text("Close", color = Color(0xFF475569))
          }
        }
      }
    }
  }
}

@Composable
fun Greeting(name: String, modifier: Modifier = Modifier) {
  Text(text = "Hello $name!", modifier = modifier)
}

@Preview(showBackground = true)
@Composable
fun GreetingPreview() {
  MyApplicationTheme { Greeting("MAV") }
}
