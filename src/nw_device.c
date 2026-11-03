/* Resource-free devices used for asynchronous regulatory firmware requests. */
#include "lx_os.h"
#include <linux/device/faux.h>
struct native_faux_device { struct faux_device device; struct faux_device_ops ops; };
static void faux_release(struct device *device) {
  struct native_faux_device *native = container_of(device, struct native_faux_device, device.dev);
  kfree(native);
}
struct faux_device *faux_device_create(const char *name, struct device *parent, const struct faux_device_ops *ops) {
  struct native_faux_device *native = kzalloc(sizeof(*native), GFP_KERNEL);
  if (!native) return ERR_PTR(-ENOMEM);
  if (ops) native->ops = *ops;
  struct device *device = &native->device.dev;
  device_initialize(device); device->release = faux_release; device->parent = parent;
  int result = dev_set_name(device, "%s", name);
  if (!result) result = device_add(device);
  if (!result && native->ops.probe) result = native->ops.probe(&native->device);
  if (result) { device_del(device); put_device(device); return ERR_PTR(result); }
  return &native->device;
}
void faux_device_destroy(struct faux_device *device) {
  if (IS_ERR_OR_NULL(device)) return;
  struct native_faux_device *native = container_of(device, struct native_faux_device, device);
  if (native->ops.remove) native->ops.remove(device);
  device_unregister(&device->dev);
}
