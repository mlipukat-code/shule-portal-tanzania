        return res.status(404).json({
          success: false,
          message:
            "Shule haipatikani au haijawezeshwa."
        });
      }

      const formResult =
        await pool.query(
          `
          SELECT
            id,
            school_id,
            form_name,
            price,
            status
          FROM school_forms
          WHERE
            id = $1
            AND school_id = $2
            AND status = 'active'
          LIMIT 1
          `,
          [
            Number(form_id),
            Number(school_id)
          ]
        );

      if (formResult.rows.length === 0) {

        return res.status(404).json({
          success: false,
          message:
            "Fomu haipatikani au haijawezeshwa."
        });
      }

      const applicationNumber =
        generateApplicationNumber();

      const result =
        await pool.query(
          `
          INSERT INTO applications
          (
            application_number,
            school_id,
            form_id,
            applicant_name,
            applicant_gender,
            applicant_date_of_birth,
            parent_name,
            parent_phone,
            parent_email,
            address,
            status,
            payment_status
          )
          VALUES
          (
            $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,
            'pending',
            'unpaid'
          )
          RETURNING *
          `,
          [
            applicationNumber,
            Number(school_id),
            Number(form_id),
            applicant_name,
            applicant_gender || null,
            applicant_date_of_birth || null,
            parent_name || null,
            parent_phone || null,
            parent_email || null,
            address || null
          ]
        );

      return res.json({
        success: true,
        message:
          "Application imepokelewa.",
        application:
          result.rows[0],
        application_number:
          applicationNumber
      });

    } catch (error) {

      console.error(
        "Create application error:",
        error
      );

      return res.status(500).json({
        success: false,
        message:
          "Imeshindikana kutuma application."
      });
    }
  }
);

// =====================================================
// PAYMENTS - ADMIN
// =====================================================

app.get(
  "/api/admin/payments",
  requireAdmin,
  async (req, res) => {

    try {

      const result = await pool.query(
        `
        SELECT
          p.*,
          a.applicant_name,
          s.name AS school_name,
          f.form_name
        FROM payments p

        LEFT JOIN applications a
          ON a.id = p.application_id

        LEFT JOIN schools s
          ON s.id = a.school_id

        LEFT JOIN school_forms f
          ON f.id = a.form_id

        ORDER BY p.id DESC
        `
      );

      return res.json({
        success: true,
        payments:
          result.rows
      });

    } catch (error) {

      console.error(
        "Get payments error:",
        error
      );

      return res.status(500).json({
        success: false,
        message:
          "Imeshindikana kupata malipo."
      });
    }
  }
);

// =====================================================
// CREATE PAYMENT RECORD
// =====================================================
// Hii bado ni payment record tu.
// Gateway halisi ya M-Pesa/Airtel/Tigo/HaloPesa
// tutaunganisha baadaye.

app.post(
  "/api/admin/payments",
  requireAdmin,
  async (req, res) => {

    try {

      const {
        application_id,
        amount,
        payment_method,
        transaction_id,
        payer_phone,
        status
      } = req.body;

      if (
        !application_id ||
        !amount
      ) {

        return res.status(400).json({
          success: false,
          message:
            "Application na kiasi cha malipo vinahitajika."
        });
      }

      const applicationResult =
        await pool.query(
          `
          SELECT
            id,
            application_number
          FROM applications
          WHERE id = $1
          LIMIT 1
          `,
          [Number(application_id)]
        );

      if (
        applicationResult.rows.length === 0
      ) {

        return res.status(404).json({
          success: false,
          message:
            "Application haijapatikana."
        });
      }

      const application =
        applicationResult.rows[0];

      const paymentReference =
        generatePaymentReference();

      const paymentStatus =
        status || "pending";

      const paidAt =
        paymentStatus === "paid"
          ? new Date()
          : null;

      const result =
        await pool.query(
          `
          INSERT INTO payments
          (
            payment_reference,
            application_id,
            application_number,
            amount,
            payment_method,
            transaction_id,
            payer_phone,
            status,
            paid_at
          )
          VALUES
          (
            $1,$2,$3,$4,$5,$6,$7,$8,$9
          )
          RETURNING *
          `,
          [
            paymentReference,
            application.id,
            application.application_number,
            Number(amount),
            payment_method || null,
            transaction_id || null,
            payer_phone || null,
            paymentStatus,
            paidAt
          ]
        );

      if (paymentStatus === "paid") {

        await pool.query(
          `
          UPDATE applications
          SET
            payment_status = 'paid',
            updated_at = CURRENT_TIMESTAMP
          WHERE id = $1
          `,
          [application.id]
        );
      }

      return res.json({
        success: true,
        message:
          "Malipo yamehifadhiwa.",
        payment:
          result.rows[0]
      });

    } catch (error) {

      console.error(
        "Create payment error:",
        error
      );

      return res.status(500).json({
        success: false,
        message:
          "Imeshindikana kuhifadhi malipo."
      });
    }
  }
);

// =====================================================
// SERVER START
// =====================================================

async function startServer() {

  try {

    await initializeDatabase();

    await syncAdminUser();

    app.listen(
      PORT,
      () => {

        console.log(
          `Shule Portal Tanzania running on port ${PORT}`
        );

      }
    );

  } catch (error) {

    console.error(
      "Server startup error:",
      error
    );

    process.exit(1);
  }
}

startServer();