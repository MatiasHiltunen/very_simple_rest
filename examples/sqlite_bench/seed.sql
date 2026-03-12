PRAGMA foreign_keys = ON;
PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;
PRAGMA temp_store = MEMORY;

BEGIN IMMEDIATE;

WITH RECURSIVE seq(n) AS (
    SELECT 1
    UNION ALL
    SELECT n + 1 FROM seq WHERE n < 25
)
INSERT INTO account (name, slug, plan_tier, is_active)
SELECT
    printf('Tenant %02d', n),
    printf('tenant-%02d', n),
    CASE n % 3
        WHEN 0 THEN 'enterprise'
        WHEN 1 THEN 'growth'
        ELSE 'starter'
    END,
    1
FROM seq;

WITH RECURSIVE seq(n) AS (
    SELECT 1
    UNION ALL
    SELECT n + 1 FROM seq WHERE n < 500
)
INSERT INTO app_user (account_id, email, display_name, role)
SELECT
    ((n - 1) / 20) + 1,
    printf('user%04d@tenant%02d.example', n, ((n - 1) / 20) + 1),
    printf('User %04d', n),
    CASE
        WHEN n % 20 = 1 THEN 'owner'
        WHEN n % 5 = 0 THEN 'manager'
        ELSE 'operator'
    END
FROM seq;

WITH RECURSIVE seq(n) AS (
    SELECT 1
    UNION ALL
    SELECT n + 1 FROM seq WHERE n < 250
)
INSERT INTO category (account_id, name, slug, sort_order)
SELECT
    ((n - 1) / 10) + 1,
    printf('Category %03d', n),
    printf('category-%03d', n),
    ((n - 1) % 10) + 1
FROM seq;

WITH RECURSIVE seq(n) AS (
    SELECT 1
    UNION ALL
    SELECT n + 1 FROM seq WHERE n < 500
)
INSERT INTO supplier (account_id, name, contact_email, country_code)
SELECT
    ((n - 1) / 20) + 1,
    printf('Supplier %03d', n),
    printf('supplier%03d@example.test', n),
    CASE n % 4
        WHEN 0 THEN 'US'
        WHEN 1 THEN 'DE'
        WHEN 2 THEN 'FI'
        ELSE 'JP'
    END
FROM seq;

WITH RECURSIVE seq(n) AS (
    SELECT 1
    UNION ALL
    SELECT n + 1 FROM seq WHERE n < 250
)
INSERT INTO warehouse (account_id, name, code, city, country_code)
SELECT
    ((n - 1) / 10) + 1,
    printf('Warehouse %03d', n),
    printf('WH-%03d', n),
    printf('City %02d', ((n - 1) % 10) + 1),
    CASE n % 4
        WHEN 0 THEN 'US'
        WHEN 1 THEN 'DE'
        WHEN 2 THEN 'FI'
        ELSE 'JP'
    END
FROM seq;

WITH RECURSIVE seq(n) AS (
    SELECT 1
    UNION ALL
    SELECT n + 1 FROM seq WHERE n < 5000
)
INSERT INTO product (
    account_id,
    category_id,
    supplier_id,
    sku,
    name,
    description,
    unit_price,
    is_active
)
SELECT
    ((n - 1) / 200) + 1,
    ((((n - 1) / 200)) * 10) + (((n - 1) % 10) + 1),
    ((((n - 1) / 200)) * 20) + (((n - 1) % 20) + 1),
    printf('SKU-%02d-%04d', ((n - 1) / 200) + 1, ((n - 1) % 200) + 1),
    printf('Product %04d', n),
    printf('Seeded benchmark product %04d', n),
    round((((n - 1) % 50) + 1) * 1.75, 2),
    CASE WHEN n % 17 = 0 THEN 0 ELSE 1 END
FROM seq;

WITH RECURSIVE seq(n) AS (
    SELECT 1
    UNION ALL
    SELECT n + 1 FROM seq WHERE n < 5000
)
INSERT INTO customer (account_id, email, full_name, segment, loyalty_points)
SELECT
    ((n - 1) / 200) + 1,
    printf('customer%04d@example.test', n),
    printf('Customer %04d', n),
    CASE n % 3
        WHEN 0 THEN 'enterprise'
        WHEN 1 THEN 'retail'
        ELSE 'vip'
    END,
    (n - 1) % 5000
FROM seq;

WITH RECURSIVE seq(n) AS (
    SELECT 1
    UNION ALL
    SELECT n + 1 FROM seq WHERE n < 10000
)
INSERT INTO address (
    customer_id,
    label,
    line1,
    city,
    region,
    postal_code,
    country_code
)
SELECT
    ((n - 1) / 2) + 1,
    CASE WHEN n % 2 = 1 THEN 'billing' ELSE 'shipping' END,
    printf('%d Benchmark Street', n),
    printf('City %02d', ((n - 1) % 50) + 1),
    printf('Region %02d', ((n - 1) % 20) + 1),
    printf('%05d', 10000 + n),
    CASE n % 4
        WHEN 0 THEN 'US'
        WHEN 1 THEN 'DE'
        WHEN 2 THEN 'FI'
        ELSE 'JP'
    END
FROM seq;

WITH RECURSIVE seq(n) AS (
    SELECT 1
    UNION ALL
    SELECT n + 1 FROM seq WHERE n < 10000
)
INSERT INTO sales_order (
    account_id,
    customer_id,
    billing_address_id,
    shipping_address_id,
    status,
    channel,
    currency,
    total_amount
)
SELECT
    ((((n - 1) / 2)) / 200) + 1,
    ((n - 1) / 2) + 1,
    ((((n - 1) / 2)) * 2) + 1,
    ((((n - 1) / 2)) * 2) + 2,
    CASE n % 5
        WHEN 0 THEN 'cancelled'
        WHEN 1 THEN 'pending'
        WHEN 2 THEN 'paid'
        WHEN 3 THEN 'packed'
        ELSE 'shipped'
    END,
    CASE n % 3
        WHEN 0 THEN 'web'
        WHEN 1 THEN 'mobile'
        ELSE 'sales'
    END,
    CASE ((((n - 1) / 2)) / 200) % 3
        WHEN 0 THEN 'USD'
        WHEN 1 THEN 'EUR'
        ELSE 'GBP'
    END,
    round(50 + ((n - 1) % 400) * 1.25, 2)
FROM seq;

WITH RECURSIVE seq(n) AS (
    SELECT 1
    UNION ALL
    SELECT n + 1 FROM seq WHERE n < 50000
)
INSERT INTO sales_order_item (
    order_id,
    product_id,
    warehouse_id,
    sku,
    quantity,
    unit_price,
    discount_amount
)
SELECT
    ((n - 1) / 5) + 1,
    ((((n - 1) / 5)) / 400) * 200 + (((n - 1) % 200) + 1),
    ((((n - 1) / 5)) / 400) * 10 + (((n - 1) % 10) + 1),
    printf(
        'SKU-%02d-%04d',
        ((((n - 1) / 5)) / 400) + 1,
        ((n - 1) % 200) + 1
    ),
    ((n - 1) % 5) + 1,
    round((((n - 1) % 50) + 5) * 2.10, 2),
    CASE WHEN n % 7 = 0 THEN 5.0 ELSE 0.0 END
FROM seq;

WITH RECURSIVE seq(n) AS (
    SELECT 1
    UNION ALL
    SELECT n + 1 FROM seq WHERE n < 10000
)
INSERT INTO payment (order_id, provider, payment_method, amount, status)
SELECT
    n,
    CASE n % 3
        WHEN 0 THEN 'adyen'
        WHEN 1 THEN 'stripe'
        ELSE 'paypal'
    END,
    CASE n % 4
        WHEN 0 THEN 'invoice'
        WHEN 1 THEN 'card'
        WHEN 2 THEN 'wallet'
        ELSE 'bank_transfer'
    END,
    round(50 + ((n - 1) % 400) * 1.25, 2),
    CASE WHEN n % 10 = 0 THEN 'refunded' ELSE 'captured' END
FROM seq;

WITH RECURSIVE seq(n) AS (
    SELECT 1
    UNION ALL
    SELECT n + 1 FROM seq WHERE n < 10000
)
INSERT INTO shipment (
    order_id,
    warehouse_id,
    carrier,
    tracking_number,
    status,
    shipped_at,
    delivered_at
)
SELECT
    n,
    (((n - 1) / 400) * 10) + (((n - 1) % 10) + 1),
    CASE n % 3
        WHEN 0 THEN 'dhl'
        WHEN 1 THEN 'fedex'
        ELSE 'ups'
    END,
    printf('TRK-%08d', n),
    CASE n % 4
        WHEN 0 THEN 'label_created'
        WHEN 1 THEN 'in_transit'
        WHEN 2 THEN 'delivered'
        ELSE 'exception'
    END,
    datetime('now', printf('-%d day', (n - 1) % 60)),
    CASE
        WHEN n % 5 = 0 THEN NULL
        ELSE datetime('now', printf('-%d day', (n - 1) % 30))
    END
FROM seq;

WITH RECURSIVE seq(n) AS (
    SELECT 1
    UNION ALL
    SELECT n + 1 FROM seq WHERE n < 50000
)
INSERT INTO shipment_item (shipment_id, order_item_id, quantity)
SELECT
    ((n - 1) / 5) + 1,
    n,
    ((n - 1) % 3) + 1
FROM seq;

WITH RECURSIVE seq(n) AS (
    SELECT 1
    UNION ALL
    SELECT n + 1 FROM seq WHERE n < 25000
)
INSERT INTO inventory_lot (
    product_id,
    warehouse_id,
    supplier_id,
    lot_code,
    quantity_on_hand,
    reserved_quantity,
    unit_cost,
    received_at
)
SELECT
    ((n - 1) % 5000) + 1,
    ((((n - 1) % 5000) / 200) * 10) + (((n - 1) % 10) + 1),
    ((((n - 1) % 5000) / 200) * 20) + (((n - 1) % 20) + 1),
    printf('LOT-%06d', n),
    ((n - 1) % 80) + 20,
    (n - 1) % 10,
    round((((n - 1) % 30) + 10) * 1.15, 2),
    datetime('now', printf('-%d day', (n - 1) % 120))
FROM seq;

WITH RECURSIVE seq(n) AS (
    SELECT 1
    UNION ALL
    SELECT n + 1 FROM seq WHERE n < 1000
)
INSERT INTO return_request (order_id, customer_id, reason, status, refund_amount)
SELECT
    n * 10,
    (((n * 10) - 1) / 2) + 1,
    CASE n % 4
        WHEN 0 THEN 'damaged'
        WHEN 1 THEN 'late_delivery'
        WHEN 2 THEN 'wrong_item'
        ELSE 'customer_remorse'
    END,
    CASE n % 3
        WHEN 0 THEN 'approved'
        WHEN 1 THEN 'received'
        ELSE 'requested'
    END,
    round(10 + (n % 40) * 2.5, 2)
FROM seq;

WITH RECURSIVE seq(n) AS (
    SELECT 1
    UNION ALL
    SELECT n + 1 FROM seq WHERE n < 2000
)
INSERT INTO return_item (return_request_id, order_item_id, quantity, resolution)
SELECT
    ((n - 1) / 2) + 1,
    (((((n - 1) / 2) + 1) * 10) - 1) * 5 + (((n - 1) % 2) + 1),
    1,
    CASE WHEN n % 2 = 0 THEN 'refund' ELSE 'restock' END
FROM seq;

WITH RECURSIVE seq(n) AS (
    SELECT 1
    UNION ALL
    SELECT n + 1 FROM seq WHERE n < 10000
)
INSERT INTO audit_event (account_id, user_id, entity_table, entity_id, action, payload)
SELECT
    ((n - 1) / 400) + 1,
    (((n - 1) / 400) * 20) + (((n - 1) % 20) + 1),
    CASE n % 4
        WHEN 0 THEN 'product'
        WHEN 1 THEN 'sales_order'
        WHEN 2 THEN 'customer'
        ELSE 'warehouse'
    END,
    CASE n % 4
        WHEN 0 THEN (((n - 1) / 400) * 200) + (((n - 1) % 200) + 1)
        WHEN 1 THEN (((n - 1) / 400) * 400) + (((n - 1) % 400) + 1)
        WHEN 2 THEN (((n - 1) / 400) * 200) + (((n - 1) % 200) + 1)
        ELSE (((n - 1) / 400) * 10) + (((n - 1) % 10) + 1)
    END,
    CASE n % 5
        WHEN 0 THEN 'delete'
        WHEN 1 THEN 'create'
        WHEN 2 THEN 'update'
        WHEN 3 THEN 'sync'
        ELSE 'ship'
    END,
    printf('{"seed":true,"sequence":%d}', n)
FROM seq;

COMMIT;
ANALYZE;
