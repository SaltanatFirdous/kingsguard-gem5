// drivers/misc/tee_contig.c
#include <linux/platform_device.h>
#include <linux/module.h>

struct device *tee_contig_dev;

static int tee_contig_probe(struct platform_device *pdev)
{
    tee_contig_dev = &pdev->dev;
    return 0;
}
static struct platform_driver tee_contig_drv = {
    .driver = { .name = "tee-contig", },
    .probe  = tee_contig_probe,
};
module_platform_driver(tee_contig_drv);

static int __init tee_contig_init(void)
{
    platform_device_register_simple("tee-contig", -1, NULL, 0);
    return 0;
}
late_initcall(tee_contig_init);
MODULE_LICENSE("GPL");
